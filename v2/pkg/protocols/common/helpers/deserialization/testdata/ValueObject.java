import java.io.*;

public class ValueObject implements Serializable {
   private String value;
   private String sideEffect;

   public ValueObject() {
       this("empty");
   }

   public ValueObject(String value) {
       this.value = value;
       this.sideEffect = java.time.LocalTime.now().toString();
   }
}
