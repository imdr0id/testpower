 public static void main(String[] args) {
        try {
            String username = "user";
            String privateKey = "myprivatekey";
            String password = "mypassword";
            String concatenated = username + ":" + privateKey + ":" + password;

            SecretKeySpec secretKey = generateKey(privateKey);
            byte[] encryptedData = encrypt(concatenated, secretKey);
            String encodedString = encodeBase256(encryptedData);

            System.out.println("Encoded String: " + encodedString);

            byte[] decodedData = decodeBase256(encodedString);
            String decryptedString = decrypt(decodedData, secretKey);

            System.out.println("Decrypted String: " + decryptedString);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKeySpec generateKey(String key) throws Exception {
        byte[] keyBytes = new byte[16];
        byte[] keyInputBytes = key.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(keyInputBytes, 0, keyBytes, 0, Math.min(keyInputBytes.length, keyBytes.length));
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encrypt(String data, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String encodeBase256(byte[] input) {
        StringBuilder builder = new StringBuilder();
        for (byte b : input) {
            builder.append(String.format("%02X", b));
        }
        return builder.toString();
    }

    private static byte[] decodeBase256(String input) {
        int len = input.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(input.charAt(i), 16) << 4)
                    + Character.digit(input.charAt(i + 1), 16));
        }
        return data;
    }

    private static String decrypt(byte[] data, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(data);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
 /*       }
    }*/

    }
