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
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.concurrent.TimeUnit;
import java.util.Base64;
import java.io.Console;

public class NationalIdManagementSystem {

    private static MongoClient mongoClient;
    private static MongoDatabase database;
    private static MongoCollection<Document> citizensCollection;
    private static MongoCollection<Document> usersCollection;
    private static MongoCollection<Document> auditLogsCollection;

    private static Blockchain nationalIdBlockchain;

    private static final String DB_NAME = "national_id_db";

    private static final int MAX_NAME = 100;
    private static final int MAX_ADDRESS = 200;
    private static final int MAX_PHONE_NUMBER = 11;
    private static final int SALT_LEN = 32;
    private static final int ITERATIONS = 100000;
    private static final int HASH_LEN = 32;

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

    public static String readPassword() {
        Console console = System.console();
        if (console != null) {
            char[] passwordChars = console.readPassword();
            if (passwordChars != null) {
                String password = new String(passwordChars);
                Arrays.fill(passwordChars, ' ');
                return password;
            }
        }
        System.out.print(" (Password input not masked in IDE) ");
        return scanner.nextLine();
    }

    public static String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        return input.trim().replace("\0", "");
    }

    public static boolean isValidName(String name) {
        String sanitizedName = sanitizeInput(name);
        return sanitizedName != null && !sanitizedName.isEmpty() && sanitizedName.length() <= MAX_NAME && sanitizedName.matches("^[a-zA-Z\\s.'-]+$");
    }

    public static boolean isValidAddress(String address) {
        String sanitizedAddress = sanitizeInput(address);
        return sanitizedAddress != null && !sanitizedAddress.isEmpty() && sanitizedAddress.length() <= MAX_ADDRESS;
    }

    public static boolean isValidPhoneNumber(String phoneNumber) {
        String sanitizedPhoneNumber = sanitizeInput(phoneNumber);
        return sanitizedPhoneNumber != null && sanitizedPhoneNumber.matches("^01[3-9]\\d{8}$");
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
        return citizensCollection.find(Filters.eq("nid", nid)).first() != null;
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LEN];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] deriveKey(String password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, HASH_LEN * 8);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            System.err.println("Error deriving key: " + e.getMessage());
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
            throw new RuntimeException(e);
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
            String calculatedhash = applySha256(
                    previousHash +
                            Long.toString(timestamp) +
                            Integer.toString(nonce) +
                            data
            );
            return calculatedhash;
        }

        public void mineBlock(int difficulty) {
            String target = new String(new char[difficulty]).replace('\0', '0');
            while (!hash.substring(0, difficulty).equals(target)) {
                nonce++;
                hash = calculateHash();
            }
            System.out.println("Block Mined!!! : " + hash);
        }
    }

    public static class Blockchain {
        public List<Block> chain;
        public int difficulty = 3;

        public Blockchain() {
            chain = new ArrayList<>();
            addBlock(new Block("Genesis Block Data", "0"));
        }

        public Block getLatestBlock() {
            return chain.get(chain.size() - 1);
        }

        public void addBlock(Block newBlock) {
            if (chain.size() > 0) {
                newBlock.previousHash = getLatestBlock().hash;
            }
            newBlock.mineBlock(difficulty);
            chain.add(newBlock);
        }

        public boolean isChainValid() {
            Block currentBlock;
            Block previousBlock;

            for (int i = 1; i < chain.size(); i++) {
                currentBlock = chain.get(i);
                previousBlock = chain.get(i - 1);

                if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                    System.out.println("Current Block has been tampered with!");
                    return false;
                }

                if (!previousBlock.hash.equals(currentBlock.previousHash)) {
                    System.out.println("Previous Block's hash doesn't match!");
                    return false;
                }
            }
            return true;
        }
    }

    public static boolean initDb() {
        try {
            mongoClient = MongoClients.create("mongodb://localhost:27017");
            database = mongoClient.getDatabase(DB_NAME);

            citizensCollection = database.getCollection("citizens");
            usersCollection = database.getCollection("users");
            auditLogsCollection = database.getCollection("audit_logs");

            nationalIdBlockchain = new Blockchain();

            System.out.println("Connected to MongoDB database: " + DB_NAME);
            System.out.println("Blockchain initialized with Genesis Block.");
            return true;
        } catch (Exception e) {
            System.err.println("Error connecting to MongoDB or initializing blockchain: " + e.getMessage());
            return false;
        }
    }

    public static Document inputCitizenDetails(String existingNid, long existingCreatedAt, boolean isNew) {
        Document citizenDoc = new Document();

        if (isNew) {
            citizenDoc.append("nid", generateUniqueNid());
            citizenDoc.append("created_at", System.currentTimeMillis() / 1000L);
            citizenDoc.append("is_active", 1);
            System.out.println("Generated NID: " + citizenDoc.getString("nid"));
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
                System.out.println("Invalid name. Must not be empty, only contains letters, spaces, hyphens, apostrophes, and be max " + MAX_NAME + " chars.");
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
            gender = sanitizeInput(scanner.nextLine());
            if (!gender.equalsIgnoreCase("Male") && !gender.equalsIgnoreCase("Female") && !gender.equalsIgnoreCase("Other")) {
                System.out.println("Invalid gender. Please enter Male, Female, or Other.");
            }
        } while (!gender.equalsIgnoreCase("Male") && !gender.equalsIgnoreCase("Female") && !gender.equalsIgnoreCase("Other"));
        citizenDoc.append("gender", gender);

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
                System.out.println("Invalid father's name. Must not be empty, only contains letters, spaces, hyphens, apostrophes, and be max " + MAX_NAME + " chars.");
            }
        } while (!isValidName(fatherName));
        citizenDoc.append("father_name", fatherName);

        String motherName;
        do {
            System.out.print("Mother Name: ");
            motherName = sanitizeInput(scanner.nextLine());
            if (!isValidName(motherName)) {
                System.out.println("Invalid mother's name. Must not be empty, only contains letters, spaces, hyphens, apostrophes, and be max " + MAX_NAME + " chars.");
            }
            } while (!isValidName(motherName));
        citizenDoc.append("mother_name", motherName);

        String[] validBloodGroups = {"A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"};
        boolean valid = false;
        String bloodGroup;
        do {
            System.out.print("Blood Group (A+/A-/B+/B-/O+/O-/AB+/AB-): ");
            bloodGroup = sanitizeInput(scanner.nextLine()).toUpperCase();
            for (String bg : validBloodGroups) {
                if (bloodGroup.equals(bg)) {
                    valid = true;
                    break;
                }
            }
            if (!valid) {
                System.out.println("Invalid blood group. Please enter a valid one.");
            }
        } while (!valid);
        citizenDoc.append("blood_group", bloodGroup);

        if (!isNew) {
            System.out.print("Is Active (1=Yes, 0=No): ");
            int isActiveStatus = scanner.nextInt();
            scanner.nextLine();
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

        System.out.printf("\nNID: %s\nName: %s\nDOB: %s\nGender: %s\nAddress: %s\nPhone: %s\nFather: %s\nMother: %s\nBlood Group: %s\nStatus: %s\nCreated: %sLast Modified: %s\nData Checksum: %s%n",
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
        Document userDoc = usersCollection.find(Filters.eq("username", sanitizedUsername)).first();

        if (userDoc == null) {
            System.out.println("User not found.");
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
                return false;
            } else {
                usersCollection.updateOne(
                    Filters.eq("username", sanitizedUsername),
                    Updates.combine(
                        Updates.set("failed_attempts", 0),
                        Updates.set("last_login_attempt", 0L)
                    )
                );
                failedAttempts = 0;
            }
        }

        byte[] dbHash = userDoc.get("password_hash", BsonBinary.class).getData();
        byte[] salt = userDoc.get("salt", BsonBinary.class).getData();

        if (dbHash.length != HASH_LEN || salt.length != SALT_LEN) {
            System.err.println("Authentication error: Stored hash or salt has incorrect length for user " + sanitizedUsername);
            return false;
        }

        byte[] derivedKey = deriveKey(password, salt);
        if (derivedKey == null) {
            return false;
        }

        boolean authenticated = Arrays.equals(dbHash, derivedKey);

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
        } else {
            int newFailedAttempts = failedAttempts + 1;
            usersCollection.updateOne(
                Filters.eq("username", sanitizedUsername),
                Updates.combine(
                    Updates.set("failed_attempts", newFailedAttempts),
                    Updates.set("last_login_attempt", currentTimeSeconds)
                )
            );
            if (newFailedAttempts >= MAX_FAILED_ATTEMPTS) {
                System.out.printf("Too many failed attempts. Account for '%s' is now locked for %d minutes.\n", sanitizedUsername, LOCKOUT_DURATION_MINUTES * (long) Math.pow(2, newFailedAttempts - MAX_FAILED_ATTEMPTS));
            }
        }
        return authenticated;
    }

    public static boolean checkSessionTimeout() {
        if (loggedInUsername == null) {
            return false;
        }
        long currentTimeSeconds = System.currentTimeMillis() / 1000L;
        if (currentTimeSeconds - lastActivityTime > TimeUnit.MINUTES.toSeconds(SESSION_TIMEOUT_MINUTES)) {
            System.out.println("\nSession timed out due to inactivity. Please log in again.");
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

        System.out.print("Enter your current password: ");
        String currentPassword = readPassword();

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
            System.out.print("Enter new password: ");
            newPassword = readPassword();
            System.out.print("Confirm new password: ");
            confirmNewPassword = readPassword();

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
            System.err.println("Failed to change password: " + e.getMessage());
        }
    }

    public static void logAudit(String performerUsername, String activityType, String targetNid) {
        Document logDoc = new Document("performer", performerUsername)
                                .append("timestamp", System.currentTimeMillis() / 1000L)
                                .append("activity_type", activityType)
                                .append("target_nid", targetNid);

        auditLogsCollection.insertOne(logDoc);

        String auditDataHashable = gson.toJson(logDoc);
        nationalIdBlockchain.addBlock(new Block(applySha256(auditDataHashable), nationalIdBlockchain.getLatestBlock().hash));
    }

    public static boolean simulateFaceScan() {
        System.out.println("\n--- Face Scan Simulation ---");
        System.out.println("In a real system, this would involve integrating with a biometric face recognition API or hardware.");
        System.out.print("Simulating face scan... (Press Enter to continue, or type 'fail' to simulate failure): ");
        String input = scanner.nextLine();
        if (input.equalsIgnoreCase("fail")) {
            System.out.println("Face scan simulation failed.");
            return false;
        }
        System.out.println("Face scan successful!");
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
            System.out.println("Citizen registered successfully!");
            logAudit(loggedInUsername, "REGISTERED_CITIZEN", newCitizenDoc.getString("nid"));

            nationalIdBlockchain.addBlock(new Block(dataChecksum, nationalIdBlockchain.getLatestBlock().hash));

        } catch (Exception e) {
            System.err.println("Failed to register citizen: " + e.getMessage());
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
    }

    public static void adminSearchCitizen() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        System.out.print("Enter NID to search: ");
        String nid = sanitizeInput(scanner.nextLine());

        Document citizenDoc = citizensCollection.find(Filters.eq("nid", nid)).first();

        if (citizenDoc != null) {
            String storedChecksum = citizenDoc.getString("data_checksum");
            String calculatedChecksum = applySha256(getCitizenDataHashableString(citizenDoc));
            if (storedChecksum != null && !storedChecksum.equals(calculatedChecksum)) {
                System.out.println("WARNING: Data integrity compromised for NID: " + citizenDoc.getString("nid") + " (Checksum mismatch)");
                logAudit(loggedInUsername, "DATA_INTEGRITY_WARNING", citizenDoc.getString("nid"));
            }
            displayCitizen(citizenDoc);
            logAudit(loggedInUsername, "SEARCHED_CITIZEN", nid);
        } else {
            System.out.println("Citizen with NID " + nid + " not found!");
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

        Document existingCitizenDoc = citizensCollection.find(Filters.eq("nid", nid)).first();

        if (existingCitizenDoc == null) {
            System.out.println("Citizen with NID " + nid + " not found!");
            return;
        }

        System.out.println("Current citizen details:");
        displayCitizen(existingCitizenDoc);
        System.out.println("\nEnter new details for citizen with NID " + nid + ":");
        
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
                    Updates.set("data_checksum", updatedCitizenDoc.getString("data_checksum"))
                )
            );
            System.out.println("Citizen updated successfully!");
            logAudit(loggedInUsername, "UPDATED_CITIZEN", nid);

            nationalIdBlockchain.addBlock(new Block(dataChecksum, nationalIdBlockchain.getLatestBlock().hash));

        } catch (Exception e) {
            System.err.println("Failed to update citizen: " + e.getMessage());
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

        Document existingCitizenDoc = citizensCollection.find(Filters.eq("nid", nid)).first();
        if (existingCitizenDoc == null) {
            System.out.println("Citizen with NID " + nid + " not found!");
            return;
        }
        
        System.out.print("Are you sure you want to delete citizen with NID " + nid + "? (yes/no): ");
        String confirmation = scanner.nextLine().trim().toLowerCase();
        if (!confirmation.equals("yes")) {
            System.out.println("Deletion cancelled.");
            return;
        }

        try {
            long deletedCount = citizensCollection.deleteOne(Filters.eq("nid", nid)).getDeletedCount();

            if (deletedCount > 0) {
                System.out.println("Citizen with NID " + nid + " deleted successfully!");
                logAudit(loggedInUsername, "DELETED_CITIZEN", nid);
                nationalIdBlockchain.addBlock(new Block(applySha256("DELETED_NID:" + nid), nationalIdBlockchain.getLatestBlock().hash));
            } else {
                System.out.println("Citizen with NID " + nid + " not found or failed to delete!");
            }
        } catch (Exception e) {
            System.err.println("Delete failed: " + e.getMessage());
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
        for (Document logDoc : auditLogsCollection.find().sort(new Document("timestamp", -1))) {
            String performer = logDoc.getString("performer");
            long timestamp = logDoc.getLong("timestamp");
            String activity = logDoc.getString("activity_type");
            String targetNid = logDoc.getString("target_nid");

            System.out.printf("Performer: %s\nActivity: %s\nTarget NID: %s\nTime: %s\n\n",
                    performer, activity, targetNid, new Date(timestamp * 1000L));
            System.out.println("----------------------------------------");
        }
        logAudit(loggedInUsername, "VIEWED_AUDIT_LOGS", "N/A");
    }

    public static void adminVerifyBlockchainIntegrity() {
        if (loggedInUsername == null) {
            System.out.println("You must be logged in to perform this action.");
            return;
        }
        if (checkSessionTimeout()) return;

        System.out.println("\nVerifying Blockchain Integrity...");
        if (nationalIdBlockchain.isChainValid()) {
            System.out.println("Blockchain is valid! No tampering detected.");
        } else {
            System.out.println("Blockchain is NOT valid! Tampering detected!");
        }
        logAudit(loggedInUsername, "VERIFIED_BLOCKCHAIN", "N/A");
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
            System.out.print("Choice: ");

            choice = scanner.nextInt();
            scanner.nextLine();

            if (checkSessionTimeout()) {
                break;
            }

            switch (choice) {
                case 1: adminRegisterCitizen(); break;
                case 2: adminViewCitizens(); break;
                case 3: adminSearchCitizen(); break;
                case 4: adminUpdateCitizen(); break;
                case 5: adminDeleteCitizen(); break;
                case 6: adminViewAuditLogs(); break;
                case 7: adminChangePassword(); break;
                case 8: adminVerifyBlockchainIntegrity(); break;
                case 9:
                    System.out.println("Logging out from Admin Panel.");
                    logAudit(loggedInUsername, "LOGOUT", "N/A");
                    loggedInUsername = null;
                    break;
                default: System.out.println("Invalid choice!");
            }
        } while (choice != 9);
    }

    public static void main(String[] args) {
        if (!initDb()) {
            System.err.println("Failed to initialize database! Exiting.");
            return;
        }

        try {
            long adminCount = usersCollection.countDocuments(Filters.eq("username", "admin"));

            if (adminCount == 0) {
                byte[] salt = generateSalt();
                String defaultPassword = "SecureAdminPass123!";
                if (!isValidPassword(defaultPassword)) {
                    System.err.println("Default admin password does not meet new policy requirements. Please change it immediately after first login.");
                }
                byte[] passwordHash = deriveKey(defaultPassword, salt);

                Document adminDoc = new Document("username", "admin")
                                            .append("password_hash", new Binary(passwordHash))
                                            .append("salt", new Binary(salt))
                                            .append("role", Role.ADMIN.ordinal())
                                            .append("failed_attempts", 0)
                                            .append("last_login", 0L)
                                            .append("last_login_attempt", 0L);

                usersCollection.insertOne(adminDoc);
                System.out.println("Admin user 'admin' created with password 'SecureAdminPass123!'");
            }
        } catch (Exception e) {
            System.err.println("Error checking/creating admin user: " + e.getMessage());
        }

        int choice;
        do {
            System.out.println("\nNATIONAL ID MANAGEMENT SYSTEM");
            System.out.println("1. Admin Login");
            System.out.println("2. Exit");
            System.out.print("Choice: ");

            choice = scanner.nextInt();
            scanner.nextLine();

            if (choice == 1) {
                System.out.print("Username: ");
                String username = scanner.nextLine();
                System.out.print("Password: ");
                String password = readPassword();

                if (authenticateUser(username, password)) {
                    System.out.println("Login successful!");
                    logAudit(username, "LOGIN_SUCCESS", "N/A");
                    adminMenu();
                } else {
                    logAudit(username, "LOGIN_FAILED", "N/A");
                }
            } else if (choice == 2) {
                System.out.println("Exiting National ID Management System.");
            } else {
                System.out.println("Invalid choice!");
            }
        } while (choice != 2);

        if (mongoClient != null) {
            mongoClient.close();
            System.out.println("MongoDB connection closed.");
        }
        if (scanner != null) {
            scanner.close();
        }
    }
}