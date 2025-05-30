import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;
import org.bson.Document;
import org.bson.BsonBinary;
import org.bson.types.Binary;
import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.concurrent.locks.ReentrantLock;
import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.InputMismatchException;

public class NationalIdManagementSystem {
    private static final Logger logger = LoggerFactory.getLogger(NationalIdManagementSystem.class);

    private static MongoClient mongoClient;
    private static MongoDatabase database;
    private static MongoCollection<Document> citizensCollection;
    private static MongoCollection<Document> usersCollection;
    private static MongoCollection<Document> auditLogsCollection;

    private static Blockchain nationalIdBlockchain;
    private static final ReentrantLock blockchainLock = new ReentrantLock();

    private static final String CONFIG_FILE = "config.properties";
    private static final String DB_NAME;
    private static final String MONGO_URI;
    private static final int BLOCKCHAIN_DIFFICULTY;

    private static final int MAX_NAME = 100;
    private static final int MAX_ADDRESS = 200;
    private static final int MAX_PHONE_NUMBER = 11;
    private static final int SALT_LEN = 32;
    private static final int ITERATIONS = 1000000; // Increased for stronger hashing
    private static final int HASH_LEN = 64; // Increased for stronger security
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MINUTES = 30;
    private static final long SESSION_TIMEOUT_MINUTES = 10;

    private static String loggedInUsername = null;
    private static long lastActivityTime = 0L;

    public enum Role {
        ADMIN
    }

    private static final Scanner scanner = new Scanner(System.in);
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Gson gson = new Gson();

    static {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(CONFIG_FILE)) {
            props.load(fis);
            DB_NAME = props.getProperty("db.name", "national_id_db");
            MONGO_URI = props.getProperty("mongo.uri", "mongodb://localhost:27017");
            BLOCKCHAIN_DIFFICULTY = Integer.parseInt(props.getProperty("blockchain.difficulty", "5"));
        } catch (IOException | NumberFormatException e) {
            logger.error("Failed to load configuration: {}", e.getMessage());
            throw new RuntimeException("Configuration loading failed", e);
        }
    }

    public static void clearInputBuffer() {
        if (scanner.hasNextLine()) {
            scanner.nextLine();
        }
    }

    public static String readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] passwordChars = console.readPassword(prompt);
            if (passwordChars != null) {
                String password = new String(passwordChars);
                Arrays.fill(passwordChars, ' ');
                return password;
            }
        }
        System.out.print(prompt + " (not masked in IDE): ");
        char[] passwordChars = scanner.nextLine().toCharArray();
        String password = new String(passwordChars);
        Arrays.fill(passwordChars, ' ');
        return password != null ? password : "";
    }

    public static String sanitizeInput(String input) {
        if (input == null) {
            return "";
        }
        // Remove potential injection characters
        return input.trim().replaceAll("[\\n\\r\\t\\0\\x0B;\"'`]", "");
    }

    public static boolean isValidName(String name) {
        String sanitizedName = sanitizeInput(name);
        return !sanitizedName.isEmpty() && sanitizedName.length() <= MAX_NAME && sanitizedName.matches("^[a-zA-Z\\s.'-]+$");
    }

    public static boolean isValidAddress(String address) {
        String sanitizedAddress = sanitizeInput(address);
        return !sanitizedAddress.isEmpty() && sanitizedAddress.length() <= MAX_ADDRESS;
    }

    public static boolean isValidPhoneNumber(String phoneNumber) {
        String sanitizedPhoneNumber = sanitizeInput(phoneNumber);
        return sanitizedPhoneNumber.matches("^01[3-9]\\d{8}$");
    }

    public static boolean validateDate(String date) {
        String sanitizedDate = sanitizeInput(date);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy");
        try {
            LocalDate parsedDate = LocalDate.parse(sanitizedDate, formatter);
            int year = parsedDate.getYear();
            int currentYear = LocalDate.now().getYear();
            return year >= 1900 && year <= (currentYear - 18);
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    public static boolean isValidPassword(String password) {
        if (password == null || password.length() < 12) {
            return false;
        }
        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        String specialChars = "!@#$%^&*()-_+=[]{}|;:'\",.<>/?`~";

        for (char ch : password.toCharArray()) {
            if (Character.isUpperCase(ch)) hasUppercase = true;
            else if (Character.isLowerCase(ch)) hasLowercase = true;
            else if (Character.isDigit(ch)) hasDigit = true;
            else if (specialChars.indexOf(ch) >= 0) hasSpecial = true;
        }
        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
    }

    public static String generateUniqueNid() {
        String nid;
        do {
            byte[] bytes = new byte[5];
            secureRandom.nextBytes(bytes);
            long randomNum = (bytes[0] & 0xFFL) << 32 | (bytes[1] & 0xFFL) << 24 | (bytes[2] & 0xFFL) << 16 | (bytes[3] & 0xFFL) << 8 | (bytes[4] & 0xFFL);
            nid = String.format("%010d", randomNum % 10000000000L);
        } while (isNidExists(nid));
        return nid;
    }

    public static boolean isNidExists(String nid) {
        try {
            return citizensCollection.find(Filters.eq("nid", nid)).first() != null;
        } catch (Exception e) {
            logger.error("Error checking NID existence: {}", e.getMessage());
            return false;
        }
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LEN];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] deriveKey(String password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, HASH_LEN * 8);
            byte[] key = factory.generateSecret(spec).getEncoded();
            Arrays.fill(password.toCharArray(), '\0');
            return key;
        } catch (Exception e) {
            logger.error("Error deriving key: {}", e.getMessage());
            return null;
        }
    }

    private static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            logger.error("SHA-256 hashing failed: {}", e.getMessage());
            throw new RuntimeException("Hashing failed", e);
        }
    }

    public static class Block {
        public String hash;
        public String previousHash;
        private String data;
        private long timestamp;
        private int nonce;

        public Block(String data, String previousHash) {
            this.data = data;
            this.previousHash = previousHash;
            this.timestamp = System.currentTimeMillis();
            this.hash = calculateHash();
        }

        public String calculateHash() {
            return applySha256(previousHash + Long.toString(timestamp) + Integer.toString(nonce) + data);
        }

        public void mineBlock(int difficulty) {
            String target = new String(new char[difficulty]).replace('\0', '0');
            while (!hash.substring(0, difficulty).equals(target)) {
                nonce++;
                hash = calculateHash();
            }
            logger.info("Block mined: {}", hash);
        }
    }

    public static class Blockchain {
        private final List<Block> chain;
        private final int difficulty;
        private final ReentrantLock lock = new ReentrantLock();

        public Blockchain(int difficulty) {
            this.difficulty = difficulty;
            chain = new ArrayList<>();
            addBlock(new Block("Genesis Block Data", "0"));
        }

        public Block getLatestBlock() {
            try (var ignored = lock.lock()) {
                return chain.get(chain.size() - 1);
            }
        }

        public void addBlock(Block newBlock) {
            try (var ignored = lock.lock()) {
                if (chain.size() > 0) {
                    newBlock.previousHash = getLatestBlock().hash;
                }
                newBlock.mineBlock(difficulty);
                chain.add(newBlock);
            }
        }

        public boolean isChainValid() {
            try (var ignored = lock.lock()) {
                for (int i = 1; i < chain.size(); i++) {
                    Block currentBlock = chain.get(i);
                    Block previousBlock = chain.get(i - 1);

                    if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                        logger.warn("Current Block tampered at index {}", i);
                        return false;
                    }

                    if (!previousBlock.hash.equals(currentBlock.previousHash)) {
                        logger.warn("Previous Block hash mismatch at index {}", i);
                        return false;
                    }
                }
                return true;
            }
        }
    }

    public static boolean initDb() {
        try {
            mongoClient = MongoClients.create(MONGO_URI);
            database = mongoClient.getDatabase(DB_NAME);
            citizensCollection = database.getCollection("citizens");
            usersCollection = database.getCollection("users");
            auditLogsCollection = database.getCollection("audit_logs");
            nationalIdBlockchain = new Blockchain(BLOCKCHAIN_DIFFICULTY);
            logger.info("Connected to MongoDB database: {}", DB_NAME);
            logger.info("Blockchain initialized with difficulty: {}", BLOCKCHAIN_DIFFICULTY);
            return true;
        } catch (Exception e) {
            logger.error("Error initializing database or blockchain: {}", e.getMessage());
            return false;
        }
    }

    public static Document inputCitizenDetails(String existingNid, long existingCreatedAt, boolean isNew) {
        Document citizenDoc = new Document();

        if (isNew) {
            citizenDoc.append("nid", generateUniqueNid());
            citizenDoc.append("created_at", System.currentTimeMillis() / 1000L);
            citizenDoc.append("is_active", 1);
            logger.info("Generated NID: {}", citizenDoc.getString("nid"));
        } else {
            citizenDoc.append("nid", existingNid);
            citizenDoc.append("created_at", existingCreatedAt);
        }

        System.out.println("\nEnter Citizen Details:");

        String name;
        do {
            System.out.print("Full Name: ");
            name = sanitizeInput(scanner.nextLine());
            if (!isValidName(name)) {
                System.out.println("Invalid name. Must not be empty, only contain letters, spaces, hyphens, apostrophes, and be max " + MAX_NAME + " chars.");
            }
        } while (!isValidName(name));
        citizenDoc.append("name", name);

        String dob;
        do {
            System.out.print("DOB (DD-MM-YYYY): ");
            dob = sanitizeInput(scanner.nextLine());
            if (!validateDate(dob)) {
                System.out.println("Invalid date format or person might be too young (must be 18+). Please enter DOB in DD-MM-YYYY format.");
            }
        } while (!validateDate(dob));
        citizenDoc.append("dob", dob);

        String gender;
        do {
            System.out.print("Gender (Male/Female/Other): ");
            gender = sanitizeInput(scanner.nextLine()).toLowerCase();
            if (!gender.equals("male") && !gender.equals("female") && !gender.equals("other")) {
                System.out.println("Invalid gender. Please enter Male, Female, or Other.");
            }
        } while (!gender.equals("male") && !gender.equals("female") && !gender.equals("other"));
        citizenDoc.append("gender", gender.substring(0, 1).toUpperCase() + gender.substring(1));

        String address;
        do {
            System.out.print("Address: ");
            address = sanitizeInput(scanner.nextLine());
            if (!isValidAddress(address)) {
                System.out.println("Invalid address. Must not be empty and be max " + MAX_ADDRESS + " chars.");
            }
        } while (!isValidAddress(address));
        citizenDoc.append("address", address);

        String phoneNumber;
        do {
            System.out.print("Phone Number (e.g., 01XXXXXXXXX): ");
            phoneNumber = sanitizeInput(scanner.nextLine());
            if (!isValidPhoneNumber(phoneNumber)) {
                System.out.println("Invalid phone number. Must be 11 digits and start with '01'.");
            }
        } while (!isValidPhoneNumber(phoneNumber));
        citizenDoc.append("phone_number", phoneNumber);

        String fatherName;
        do {
            System.out.print("Father Name: ");
            fatherName = sanitizeInput(scanner.nextLine());
            if (!isValidName(fatherName)) {
                System.out.println("Invalid father's name. Must not be empty, only contain letters, spaces, hyphens, apostrophes, and be max " + MAX_NAME + " chars.");
            }
        } while (!isValidName(fatherName));
        citizenDoc.append("father_name", fatherName);

        String motherName;
        do {
            System.out.print("Mother Name: ");
            motherName = sanitizeInput(scanner.nextLine());
            if (!isValidName(motherName)) {
                System.out.println("Invalid mother's name. Must not be empty, only contain letters, spaces, hyphens, apostrophes, and be max " + MAX_NAME + " chars.");
            }
        } while (!isValidName(motherName));
        citizenDoc.append("mother_name", motherName);

        String[] validBloodGroups = {"A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"};
        String bloodGroup;
        do {
            System.out.print("Blood Group (A+/A-/B+/B-/O+/O-/AB+/AB-): ");
            bloodGroup = sanitizeInput(scanner.nextLine()).toUpperCase();
            if (!Arrays.asList(validBloodGroups).contains(bloodGroup)) {
                System.out.println("Invalid blood group. Please enter a valid one.");
            }
        } while (!Arrays.asList(validBloodGroups).contains(bloodGroup));
        citizenDoc.append("blood_group", bloodGroup);

        if (!isNew) {
            int isActiveStatus;
            do {
                System.out.print("Is Active (1=Yes, 0=No): ");
                try {
                    isActiveStatus = scanner.nextInt();
                    if (isActiveStatus != 0 && isActiveStatus != 1) {
                        System.out.println("Invalid input. Please enter 1 for Yes or 0 for No.");
                    }
                } catch (InputMismatchException e) {
                    System.out.println("Invalid input. Please enter a number (1 or 0).");
                    scanner.nextLine();
                    isActiveStatus = -1;
                }
            } while (isActiveStatus != 0 && isActiveStatus != 1);
            clearInputBuffer();
            citizenDoc.append("is_active", isActiveStatus);
        }

        citizenDoc.append("last_modified", System.currentTimeMillis() / 1000L);
        return citizenDoc;
    }

    public static void displayCitizen(Document citizenDoc) {
        String nid = citizenDoc.getString("nid");
        String name = citizenDoc.getString("name");
        String dob = citizenDoc.getString("dob");
        String gender = citizenDoc.getString("gender");
        String address = citizenDoc.getString("address");
        String phoneNumber = citizenDoc.getString("phone_number");
        String fatherName = citizenDoc.getString("father_name");
        String motherName = citizenDoc.getString("mother_name");
        String bloodGroup = citizenDoc.getString("blood_group");
        int isActive = citizenDoc.getInteger("is_active");
        long createdAt = citizenDoc.getLong("created_at");
        long lastModified = citizenDoc.getLong("last_modified");
        String dataChecksum = citizenDoc.getString("data_checksum");

        System.out.printf("\nNID: %s\nName: %s\nDOB: %s\nGender: %s\nAddress: %s\nPhone: %s\nFather: %s\nMother: %s\nBlood Group: %s\nStatus: %s\nCreated: %s\nLast Modified: %s\nData Checksum: %s%n",
                nid, name, dob, gender, address, phoneNumber, fatherName,
                motherName, bloodGroup, isActive == 1 ? "Active" : "Inactive",
                new Date(createdAt * 1000L), new Date(lastModified * 1000L), dataChecksum);
    }

    private static String getCitizenDataHashableString(Document citizenDoc) {
        Document dataToHash = new Document();
        dataToHash.append("nid", citizenDoc.getString("nid"));
        dataToHash.append("name", citizenDoc.getString("name"));
        dataToHash.append("dob", citizenDoc.getString("dob"));
        dataToHash.append("gender", citizenDoc.getString("gender"));
        dataToHash.append("address", citizenDoc.getString("address"));
        dataToHash.append("phone_number", citizenDoc.getString("phone_number"));
        dataToHash.append("father_name", citizenDoc.getString("father_name"));
        dataToHash.append("mother_name", citizenDoc.getString("mother_name"));
        dataToHash.append("blood_group", citizenDoc.getString("blood_group"));
        return gson.toJson(dataToHash);
    }

    public static boolean authenticateUser(String username, String password) {
        String sanitizedUsername = sanitizeInput(username);
        Document userDoc;
        try {
            userDoc = usersCollection.find(Filters.eq("username", sanitizedUsername)).first();
        } catch (Exception e) {
            logger.error("Error fetching user {}: {}", sanitizedUsername, e.getMessage());
            return false;
        }

        if (userDoc == null) {
            logger.warn("User not found: {}", sanitizedUsername);
            logAudit(sanitizedUsername, "LOGIN_FAILED_USER_NOT_FOUND", "N/A");
            return false;
        }

        int failedAttempts = userDoc.getInteger("failed_attempts", 0);
        long lastLoginAttemptSeconds = userDoc.getLong("last_login_attempt", 0L);
        long currentTimeSeconds = System.currentTimeMillis() / 1000L;

        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            long timeElapsedSinceLockout = currentTimeSeconds - lastLoginAttemptSeconds;
            long requiredLockoutSeconds = TimeUnit.MINUTES.toSeconds(LOCKOUT_DURATION_MINUTES * (long) Math.pow(2, failedAttempts - MAX_FAILED_ATTEMPTS));

            if (timeElapsedSinceLockout < requiredLockoutSeconds) {
                long timeLeft = requiredLockoutSeconds - timeElapsedSinceLockout;
                System.out.printf("Account locked. Please try again in %d seconds.\n", timeLeft);
                logAudit(sanitizedUsername, "LOGIN_FAILED_ACCOUNT_LOCKED", "N/A");
                return false;
            } else {
                try {
                    usersCollection.updateOne(
                            Filters.eq("username", sanitizedUsername),
                            Updates.combine(
                                    Updates.set("failed_attempts", 0),
                                    Updates.set("last_login_attempt", 0L)
                            )
                    );
                    failedAttempts = 0;
                } catch (Exception e) {
                    logger.error("Error resetting failed attempts for {}: {}", sanitizedUsername, e.getMessage());
                    return false;
                }
            }
        }

        byte[] dbHash = userDoc.get("password_hash", BsonBinary.class).getData();
        byte[] salt = userDoc.get("salt", BsonBinary.class).getData();

        if (dbHash.length != HASH_LEN || salt.length != SALT_LEN) {
            logger.error("Invalid hash or salt length for user: {}", sanitizedUsername);
            logAudit(sanitizedUsername, "LOGIN_FAILED_INVALID_HASH", "N/A");
            return false;
        }

        byte[] derivedKey = deriveKey(password, salt);
        if (derivedKey == null) {
            logAudit(sanitizedUsername, "LOGIN_FAILED_KEY_DERIVATION", "N/A");
            return false;
        }

        boolean authenticated = Arrays.equals(dbHash, derivedKey);

        try {
            if (authenticated) {
                usersCollection.updateOne(
                        Filters.eq("username", sanitizedUsername),
                        Updates.combine(
                                Updates.set("failed_attempts", 0),
                                Updates.set("last_login", currentTimeSeconds),
                                Updates.set("last_login_attempt", 0L)
                        )
                );
                loggedInUsername = sanitizedUsername;
                lastActivityTime = currentTimeSeconds;
                logAudit(sanitizedUsername, "LOGIN_SUCCESS", "N/A");
            } else {
                int newFailedAttempts = failedAttempts + 1;
                usersCollection.updateOne(
                        Filters.eq("username", sanitizedUsername),
                        Updates.combine(
                                Updates.set("failed_attempts", newFailedAttempts),
                                Updates.set("last_login_attempt", currentTimeSeconds)
                        )
                );
                System.out.println("Invalid password.");
                logAudit(sanitizedUsername, "LOGIN_FAILED_INVALID_PASSWORD", "N/A");
                if (newFailedAttempts >= MAX_FAILED_ATTEMPTS) {
                    System.out.printf("Too many failed attempts. Account for '%s' is now locked for %d minutes.\n", sanitizedUsername, LOCKOUT_DURATION_MINUTES * (long) Math.pow(2, newFailedAttempts - MAX_FAILED_ATTEMPTS));
                }
            }
        } catch (Exception e) {
            logger.error("Error updating user login status for {}: {}", sanitizedUsername, e.getMessage());
            return false;
        }
        return authenticated;
    }

    public static boolean checkSessionTimeout() {
        if (loggedInUsername == null) {
            return false;
        }
        long currentTimeSeconds = System.currentTimeMillis() / 1000L;
        if (currentTimeSeconds - lastActivityTime > TimeUnit.MINUTES.toSeconds(SESSION_TIMEOUT_MINUTES)) {
            logger.info("Session timed out for user: {}", loggedInUsername);
            logAudit(loggedInUsername, "SESSION_TIMEOUT", "N/A");
            loggedInUsername = null;
            return true;
        }
        lastActivityTime = currentTimeSeconds;
        return false;
    }

    public static void adminChangePassword() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to change your password.");
            return;
        }
        if (checkSessionTimeout()) return;

        String currentPassword = readPassword("Enter current password: ");
        String tempLoggedInUser = loggedInUsername;
        loggedInUsername = null;
        if (!authenticateUser(tempLoggedInUser, currentPassword)) {
            System.out.println("Current password incorrect. Password change failed.");
            loggedInUsername = tempLoggedInUser;
            return;
        }
        loggedInUsername = tempLoggedInUser;

        String newPassword;
        String confirmNewPassword;
        do {
            newPassword = readPassword("Enter new password: ");
            confirmNewPassword = readPassword("Confirm new password: ");

            if (!newPassword.equals(confirmNewPassword)) {
                System.out.println("New passwords do not match. Please try again.");
            } else if (!isValidPassword(newPassword)) {
                System.out.println("Password must be at least 12 characters long and contain at least one uppercase, lowercase, digit, and special character.");
            } else if (newPassword.equals(currentPassword)) {
                System.out.println("New password cannot be the same as the current password.");
            }
        } while (!newPassword.equals(confirmNewPassword) || !isValidPassword(newPassword) || newPassword.equals(currentPassword));

        byte[] newSalt = generateSalt();
        byte[] newPasswordHash = deriveKey(newPassword, newSalt);

        try {
            usersCollection.updateOne(
                    Filters.eq("username", loggedInUsername),
                    Updates.combine(
                            Updates.set("password_hash", new Binary(newPasswordHash)),
                            Updates.set("salt", new Binary(newSalt))
                    )
            );
            System.out.println("Password changed successfully for " + loggedInUsername);
            logAudit(loggedInUsername, "PASSWORD_CHANGE", "Self-password change");
        } catch (Exception e) {
            logger.error("Failed to change password for {}: {}", loggedInUsername, e.getMessage());
            logAudit(loggedInUsername, "PASSWORD_CHANGE_FAILED", "N/A");
        }
    }

    public static void logAudit(String performerUsername, String activityType, String targetNid) {
        Document logDoc = new Document("performer", performerUsername)
                .append("timestamp", System.currentTimeMillis() / 1000L)
                .append("activity_type", activityType)
                .append("target_nid", targetNid)
                .append("ip_address", "localhost") // Placeholder for real IP
                .append("session_id", loggedInUsername != null ? applySha256(loggedInUsername + System.currentTimeMillis()) : "N/A");

        try {
            auditLogsCollection.insertOne(logDoc);
            String auditDataHashable = gson.toJson(logDoc);
            try (var ignored = blockchainLock.lock()) {
                nationalIdBlockchain.addBlock(new Block(applySha256(auditDataHashable), nationalIdBlockchain.getLatestBlock().hash));
            }
            logger.info("Audit logged: {} by {} for NID {}", activityType, performerUsername, targetNid);
        } catch (Exception e) {
            logger.error("Failed to log audit: {}", e.getMessage());
        }
    }

    public static boolean simulateFaceScan() {
        System.out.println("\n--- AI-Based Face Scan Simulation ---");
        System.out.println("In a real system, this would integrate with an AI face recognition model (e.g., OpenCV, AWS Rekognition).");
        System.out.print("Simulating face scan... (Press Enter to continue, or type 'fail' to simulate failure): ");
        String input = scanner.nextLine();
        if (input.equalsIgnoreCase("fail")) {
            System.out.println("AI face scan simulation failed.");
            logger.warn("Face scan failed for user: {}", loggedInUsername);
            return false;
        }
        // Simulate AI confidence score
        double confidence = secureRandom.nextDouble() * 100;
        if (confidence < 90) {
            System.out.printf("AI face scan failed: Confidence score %.2f%% is below threshold (90%%).\n", confidence);
            logger.warn("Face scan failed with confidence score: {}%", confidence);
            return false;
        }
        System.out.printf("AI face scan successful: Confidence score %.2f%%\n", confidence);
        logger.info("Face scan succeeded with confidence score: {}%", confidence);
        return true;
    }

    public static void adminRegisterCitizen() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        if (!simulateFaceScan()) {
            System.out.println("Citizen registration aborted due to failed face scan.");
            logAudit(loggedInUsername, "REGISTER_ABORTED_FACE_SCAN_FAIL", "N/A");
            return;
        }

        Document newCitizenDoc = inputCitizenDetails(null, 0, true);
        try {
            String citizenDataHashable = getCitizenDataHashableString(newCitizenDoc);
            String dataChecksum = applySha256(citizenDataHashable);
            newCitizenDoc.append("data_checksum", dataChecksum);
            citizensCollection.insertOne(newCitizenDoc);
            try (var ignored = blockchainLock.lock()) {
                nationalIdBlockchain.addBlock(new Block(dataChecksum, nationalIdBlockchain.getLatestBlock().hash));
            } catch (Exception e) {
                citizensCollection.deleteOne(Filters.eq("nid", newCitizenDoc.getString("nid")));
                throw new RuntimeException("Blockchain operation failed, rolled back MongoDB insert", e);
            }
            System.out.println("Citizen registered successfully!");
            logAudit(loggedInUsername, "REGISTERED_CITIZEN", newCitizenDoc.getString("nid"));
        } catch (Exception e) {
            logger.error("Failed to register citizen: {}", e.getMessage());
            logAudit(loggedInUsername, "REGISTER_FAILED", newCitizenDoc.getString("nid"));
        }
    }

    public static void adminViewCitizens() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        System.out.println("\nRegistered Citizens:");
        int count = 0;
        try {
            for (Document citizenDoc : citizensCollection.find()) {
                String storedChecksum = citizenDoc.getString("data_checksum");
                String calculatedChecksum = applySha256(getCitizenDataHashableString(citizenDoc));
                if (storedChecksum != null && !storedChecksum.equals(calculatedChecksum)) {
                    System.out.println("WARNING: Data integrity compromised for NID: " + citizenDoc.getString("nid") + " (Checksum mismatch)");
                    logAudit(loggedInUsername, "DATA_INTEGRITY_WARNING", citizenDoc.getString("nid"));
                }

                displayCitizen(citizenDoc);
                System.out.println("-----------------------------\n");
                count++;
            }
            if (count == 0) {
                System.out.println("No citizens registered yet!\n");
            }
            logAudit(loggedInUsername, "VIEWED_ALL_CITIZENS", "N/A");
        } catch (Exception e) {
            logger.error("Error viewing citizens: {}", e.getMessage());
            logAudit(loggedInUsername, "VIEW_CITIZENS_FAILED", "N/A");
        }
    }

    public static void adminSearchCitizen() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        System.out.print("Enter NID to search: ");
        String nid = sanitizeInput(scanner.nextLine());

        try {
            Document citizenDoc = citizensCollection.find(Filters.eq("nid", nid)).first();
            if (citizenDoc != null) {
                String storedChecksum = citizenDoc.getString("data_checksum");
                String calculatedChecksum = applySha256(getCitizenDataHashableString(citizenDoc));
                if (storedChecksum != null && !storedChecksum.equals(calculatedChecksum)) {
                    System.out.println("WARNING: Data integrity compromised for NID: " + citizenDoc.getString("nid") + " (Checksum mismatch)");
                    logAudit(loggedInUsername, "DATA_INTEGRITY_WARNING", nid);
                }
                displayCitizen(citizenDoc);
                logAudit(loggedInUsername, "SEARCHED_CITIZEN", nid);
            } else {
                System.out.println("Citizen with NID " + nid + " not found!");
                logAudit(loggedInUsername, "SEARCH_FAILED", nid);
            }
        } catch (Exception e) {
            logger.error("Error searching citizen: {}", e.getMessage());
            logAudit(loggedInUsername, "SEARCH_FAILED", nid);
        }
    }

    public static void adminUpdateCitizen() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        System.out.print("Enter NID to update: ");
        String nid = sanitizeInput(scanner.nextLine());

        Document existingCitizenDoc;
        try {
            existingCitizenDoc = citizensCollection.find(Filters.eq("nid", nid)).first();
            if (existingCitizenDoc == null) {
                System.out.println("Citizen with NID " + nid + " not found!");
                logAudit(loggedInUsername, "UPDATE_FAILED_NOT_FOUND", nid);
                return;
            }
        } catch (Exception e) {
            logger.error("Error finding citizen: {}", e.getMessage());
            logAudit(loggedInUsername, "UPDATE_FAILED", nid);
            return;
        }

        System.out.println("Enter new details for citizen with NID " + nid + ":");
        Document updatedCitizenDoc = inputCitizenDetails(nid, existingCitizenDoc.getLong("created_at"), false);

        try {
            String citizenDataHashable = getCitizenDataHashableString(updatedCitizenDoc);
            String dataChecksum = applySha256(citizenDataHashable);
            updatedCitizenDoc.append("data_checksum", dataChecksum);

            citizensCollection.updateOne(
                    Filters.eq("nid", nid),
                    Updates.combine(
                            Updates.set("name", updatedCitizenDoc.getString("name")),
                            Updates.set("dob", updatedCitizenDoc.getString("dob")),
                            Updates.set("gender", updatedCitizenDoc.getString("gender")),
                            Updates.set("address", updatedCitizenDoc.getString("address")),
                            Updates.set("phone_number", updatedCitizenDoc.getString("phone_number")),
                            Updates.set("father_name", updatedCitizenDoc.getString("father_name")),
                            Updates.set("mother_name", updatedCitizenDoc.getString("mother_name")),
                            Updates.set("blood_group", updatedCitizenDoc.getString("blood_group")),
                            Updates.set("is_active", updatedCitizenDoc.getInteger("is_active")),
                            Updates.set("last_modified", updatedCitizenDoc.getLong("last_modified")),
                            Updates.set("data_checksum", dataChecksum)
                    )
            );
            try (var ignored = blockchainLock.lock()) {
                nationalIdBlockchain.addBlock(new Block(dataChecksum, nationalIdBlockchain.getLatestBlock().hash));
            } catch (Exception e) {
                citizensCollection.updateOne(
                        Filters.eq("nid", nid),
                        Updates.combine(
                                Updates.set("name", existingCitizenDoc.getString("name")),
                                Updates.set("dob", existingCitizenDoc.getString("dob")),
                                Updates.set("gender", existingCitizenDoc.getString("gender")),
                                Updates.set("address", existingCitizenDoc.getString("address")),
                                Updates.set("phone_number", existingCitizenDoc.getString("phone_number")),
                                Updates.set("father_name", existingCitizenDoc.getString("father_name")),
                                Updates.set("mother_name", existingCitizenDoc.getString("mother_name")),
                                Updates.set("blood_group", existingCitizenDoc.getString("blood_group")),
                                Updates.set("is_active", existingCitizenDoc.getInteger("is_active")),
                                Updates.set("last_modified", existingCitizenDoc.getLong("last_modified")),
                                Updates.set("data_checksum", existingCitizenDoc.getString("data_checksum"))
                        )
                );
                throw new RuntimeException("Blockchain operation failed, rolled back MongoDB update", e);
            }
            System.out.println("Citizen updated successfully!");
            logAudit(loggedInUsername, "UPDATED_CITIZEN", nid);
        } catch (Exception e) {
            logger.error("Failed to update citizen: {}", e.getMessage());
            logAudit(loggedInUsername, "UPDATE_FAILED", nid);
        }
    }

    public static void adminDeleteCitizen() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        System.out.print("Enter NID to delete: ");
        String nid = sanitizeInput(scanner.nextLine());

        Document existingCitizenDoc;
        try {
            existingCitizenDoc = citizensCollection.find(Filters.eq("nid", nid)).first();
            if (existingCitizenDoc == null) {
                System.out.println("Citizen with NID " + nid + " not found!");
                logAudit(loggedInUsername, "DELETE_FAILED_NOT_FOUND", nid);
                return;
            }
        } catch (Exception e) {
            logger.error("Error finding citizen: {}", e.getMessage());
            logAudit(loggedInUsername, "DELETE_FAILED", nid);
            return;
        }

        try {
            long deletedCount = citizensCollection.deleteOne(Filters.eq("nid", nid)).getDeletedCount();
            if (deletedCount > 0) {
                try (var ignored = blockchainLock.lock()) {
                    nationalIdBlockchain.addBlock(new Block(applySha256("DELETED_NID:" + nid), nationalIdBlockchain.getLatestBlock().hash));
                } catch (Exception e) {
                    citizensCollection.insertOne(existingCitizenDoc);
                    throw new RuntimeException("Blockchain operation failed, rolled back MongoDB delete", e);
                }
                System.out.println("Citizen with NID " + nid + " deleted successfully!");
                logAudit(loggedInUsername, "DELETED_CITIZEN", nid);
            } else {
                System.out.println("Citizen with NID " + nid + " not found or failed to delete!");
                logAudit(loggedInUsername, "DELETE_FAILED", nid);
            }
        } catch (Exception e) {
            logger.error("Delete failed: {}", e.getMessage());
            logAudit(loggedInUsername, "DELETE_FAILED", nid);
        }
    }

    public static void adminViewAuditLogs() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        System.out.println("\nAudit Logs:");
        System.out.println("----------------------------------------");
        try {
            for (Document logDoc : auditLogsCollection.find().sort(new Document("timestamp", -1))) {
                String performer = logDoc.getString("performer");
                long timestamp = logDoc.getLong("timestamp");
                String activity = logDoc.getString("activity_type");
                String targetNid = logDoc.getString("target_nid");
                String ipAddress = logDoc.getString("ip_address");
                String sessionId = logDoc.getString("session_id");

                System.out.printf("Performer: %s\nActivity: %s\nTarget NID: %s\nIP: %s\nSession ID: %s\nTime: %s\n\n",
                        performer, activity, targetNid, ipAddress, sessionId, new Date(timestamp * 1000L));
                System.out.println("----------------------------------------");
            }
            logAudit(loggedInUsername, "VIEWED_AUDIT_LOGS", "N/A");
        } catch (Exception e) {
            logger.error("Error viewing audit logs: {}", e.getMessage());
            logAudit(loggedInUsername, "VIEW_AUDIT_LOGS_FAILED", "N/A");
        }
    }

    public static void adminVerifyBlockchainIntegrity() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        System.out.println("\nVerifying Blockchain Integrity...");
        try {
            if (nationalIdBlockchain.isChainValid()) {
                System.out.println("Blockchain is valid! No tampering detected.");
                logAudit(loggedInUsername, "VERIFIED_BLOCKCHAIN_SUCCESS", "N/A");
            } else {
                System.out.println("Blockchain is NOT valid! Tampering detected!");
                logAudit(loggedInUsername, "VERIFIED_BLOCKCHAIN_FAILED", "N/A");
            }
        } catch (Exception e) {
            logger.error("Error verifying blockchain: {}", e.getMessage());
            logAudit(loggedInUsername, "VERIFY_BLOCKCHAIN_FAILED", "N/A");
        }
    }

    public static int getMenuChoice(int maxOption) {
        while (true) {
            try {
                System.out.print("Choice: ");
                int choice = scanner.nextInt();
                clearInputBuffer();
                if (choice < 1 || choice > maxOption) {
                    System.out.println("Invalid choice! Please enter a number between 1 and " + maxOption + ".");
                    continue;
                }
                return choice;
            } catch (InputMismatchException e) {
                System.out.println("Invalid input. Please enter a number.");
                clearInputBuffer();
            }
        }
    }

    public static void adminMenu() {
        int choice;
        do {
            System.out.println("\nADMIN PANEL - Logged in as: " + loggedInUsername);
            System.out.println("1. Register Citizen");
            System.out.println("2. View Citizens");
            System.out.println("3. Search Citizen");
            System.out.println("4. Update Citizen");
            System.out.println("5. Delete Citizen");
            System.out.println("6. View Audit Logs");
            System.out.println("7. Change My Password");
            System.out.println("8. Verify Blockchain Integrity");
            System.out.println("9. Logout");
            choice = getMenuChoice(9);

            if (checkSessionTimeout()) {
                break;
            }

            switch (choice) {
                case 1:
                    adminRegisterCitizen();
                    break;
                case 2:
                    adminViewCitizens();
                    break;
                case 3:
                    adminSearchCitizen();
                    break;
                case 4:
                    adminUpdateCitizen();
                    break;
                case 5:
                    adminDeleteCitizen();
                    break;
                case 6:
                    adminViewAuditLogs();
                    break;
                case 7:
                    adminChangePassword();
                    break;
                case 8:
                    adminVerifyBlockchainIntegrity();
                    break;
                case 9:
                    System.out.println("Logging out from Admin Panel.");
                    logAudit(loggedInUsername, "LOGOUT", "N/A");
                    loggedInUsername = null;
                    break;
            }
        } while (choice != 9);
    }

    public static void main(String[] args) {
        try (MongoClient mongoClient = MongoClients.create(MONGO_URI);
             Scanner scanner = new Scanner(System.in)) {
            NationalIdManagementSystem.mongoClient = mongoClient;
            NationalIdManagementSystem.scanner = scanner;

            if (!initDb()) {
                logger.error("Failed to initialize database! Exiting.");
                return;
            }

            try {
                long adminCount = usersCollection.countDocuments(Filters.eq("username", "pub22$"));
                if (adminCount == 0) {
                    System.out.println("Creating default admin user 'pub22$'.");
                    String defaultPassword = readPassword("Enter initial admin password for 'pub22$': ");
                    while (!isValidPassword(defaultPassword)) {
                        System.out.println("Password must be at least 12 characters with uppercase, lowercase, digit, and special character.");
                        defaultPassword = readPassword("Enter initial admin password for 'pub22$': ");
                    }
                    byte[] salt = generateSalt();
                    byte[] passwordHash = deriveKey(defaultPassword, salt);

                    Document adminDoc = new Document("username", "pub22$")
                            .append("password_hash", new Binary(passwordHash))
                            .append("salt", new Binary(salt))
                            .append("role", Role.ADMIN.ordinal())
                            .append("failed_attempts", 0)
                            .append("last_login", 0L)
                            .append("last_login_attempt", 0L);

                    usersCollection.insertOne(adminDoc);
                    System.out.println("Admin user 'pub22$' created successfully.");
                    logAudit("SYSTEM", "ADMIN_CREATED", "pub22$");
                }
            } catch (Exception e) {
                logger.error("Error creating admin user: {}", e.getMessage());
                return;
            }

            int choice;
            do {
                System.out.println("\nNATIONAL ID MANAGEMENT SYSTEM");
                System.out.println("1. Admin Login");
                System.out.println("2. Exit");
                choice = getMenuChoice(2);

                if (choice == 1) {
                    System.out.print("Username: ");
                    String username = sanitizeInput(scanner.nextLine());
                    String password = readPassword("Password: ");

                    if (authenticateUser(username, password)) {
                        System.out.println("Login successful!");
                        adminMenu();
                    }
                } else if (choice == 2) {
                    System.out.println("Exiting National ID Management System.");
                }
            } while (choice != 2);
        } catch (Exception e) {
            logger.error("Unexpected error: {}", e.getMessage());
        }
    }
}