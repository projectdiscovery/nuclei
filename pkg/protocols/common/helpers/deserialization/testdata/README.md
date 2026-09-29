# testdata

### Test Unsafe Java Deserialization

```
javac Deserialize.java ValueObject.java
# generate payload and write to ValueObject2.ser
java Deserialize
```

Modified From: https://snyk.io/blog/serialization-and-deserialization-in-java/