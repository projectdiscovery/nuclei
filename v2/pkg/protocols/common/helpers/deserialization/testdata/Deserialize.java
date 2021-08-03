import java.io.*;

class Deserialize {  
    public static void main(String args[]) {
        FileInputStream fileIn = null;
        ObjectInputStream in = null;
        ValueObject vo2 = null;

        try {
            fileIn = new FileInputStream("ValueObject2.ser");
        }
        catch(FileNotFoundException e) {
            e.printStackTrace();
        }

       try {
            in = new ObjectInputStream(fileIn);
        }
        catch(IOException e) {
            e.printStackTrace();
        }
        try {
            vo2 = (ValueObject) in.readObject();
        }
        catch(Exception e) {
            e.printStackTrace();
        }
        System.out.println(vo2);
    }
}