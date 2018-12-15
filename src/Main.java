import javax.swing.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        // GUI stuff
        JFrame frame = new JFrame("Schnorr");
        View view = new View();
        frame.setContentPane(view.rootPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);

        // Generates Schnorr group numbers and saves it to file
        view.generateGroupButton.addActionListener(event -> {
            SchnorrGroup group = SchnorrGroup.generate(16);

            BigInteger[] groupArray = { group.p, group.q, group.g };
            writeNumbers(view.groupInput.getText(), groupArray);
        });

        // Sign file
        view.signButton.addActionListener(event -> {
            // Read shcnorr group from file
            SchnorrGroup group = getGroup(view);

            // Generates private key X and public key Y
            BigInteger[] keys = Schnorr.generateKeys(group);
            BigInteger x = keys[0];
            BigInteger y = keys[1];

            byte[] message = readFile(view.fileInput.getText());

            BigInteger[] signature = Schnorr.sign(group, message, x);

            // Save public key Y and signature { e, s }
            BigInteger[] publicKeyAndSignature = { y, signature[0], signature[1] };
            writeNumbers(view.signatureInput.getText(), publicKeyAndSignature);
        });


        // Verifies signature
        view.verifyButton.addActionListener(event -> {
            // Read numbers from previously generated file
            SchnorrGroup group = getGroup(view);

            // Read public key and signature
            BigInteger[] publicKeyAndSignature = readNumbers(view.signatureInput.getText());
            BigInteger y = publicKeyAndSignature[0];
            BigInteger[] signature = { publicKeyAndSignature[1], publicKeyAndSignature[2] };

            byte[] message = readFile(view.fileInput.getText());

            boolean isValid = Schnorr.isValid(group, signature, message, y);

            view.verificationStatus.setText(
                    isValid
                            ? "Signature is valid"
                            : "Signature is invalid"
            );
        });
    }

    /**
     * Gets filename from view input, reads and parses schnorr group numbers
     */
    static SchnorrGroup getGroup(View view) {
        BigInteger[] numbers = readNumbers(view.groupInput.getText());

        return new SchnorrGroup(numbers[0], numbers[1], numbers[2]);
    }

    /**
     * Writes bigints to file line by line
     */
    static void writeNumbers(String path, BigInteger[] numbers) {
        PrintWriter printWriter = null;
        try {
            printWriter = new PrintWriter(new File(path));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        for (BigInteger element : numbers){
            printWriter.println(element);
        }
        printWriter.close();
    }

    /**
     * Reads bigints from file line by line
     */
    static BigInteger[] readNumbers(String path) {
        Scanner scanner = null;
        try {
            scanner = new Scanner(new FileReader(path));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        ArrayList<BigInteger> numbers = new ArrayList<BigInteger>();
        while (scanner.hasNextBigInteger()){
            numbers.add(scanner.nextBigInteger());
        }
        scanner.close();

        return numbers.toArray(new BigInteger[0]);
    }

    static byte[] readFile(String path) {
        File f = new File(path);

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(f.toPath());
        } catch (IOException e1) {
            e1.printStackTrace();
            return new byte[]{};
        }

        return bytes;
    }
}
