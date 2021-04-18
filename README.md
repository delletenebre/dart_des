# dart_des

This algorithm is a pure dart implementation of the DES and Triple DES algorithms
(port of [pyDES](https://github.com/twhiteman/pyDes)).
Triple DES is either DES-EDE3 with a 24 byte key, or DES-EDE2 with a 16 byte key.

### Example

```dart
import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:dart_des/dart_des.dart';

main() {
  String key = '12345678'; // 8-byte
  String message = 'Driving in from the edge of town';
  List<int> encrypted;
  List<int> decrypted;
  List<int> iv = [1, 2, 3, 4, 5, 6, 7, 8];

  print('key: $key');
  print('message: $message');

  DES desECB = DES(key: key.codeUnits, mode: DESMode.ECB);
  encrypted = desECB.encrypt(message.codeUnits);
  decrypted = desECB.decrypt(encrypted);
  print('DES mode: ECB');
  print('encrypted: $encrypted');
  print('encrypted (hex): ${hex.encode(encrypted)}');
  print('encrypted (base64): ${base64.encode(encrypted)}');
  print('decrypted: $decrypted');
  print('decrypted (hex): ${hex.encode(decrypted)}');
  print('decrypted (utf8): ${utf8.decode(decrypted)}');

  key = '123456781234567812345678'; // 24-byte
  DES3 des3CBC = DES3(key: key.codeUnits, mode: DESMode.CBC, iv: iv);
  encrypted = des3CBC.encrypt(message.codeUnits);
  decrypted = des3CBC.decrypt(encrypted);
  print('Triple DES mode: CBC');
  print('encrypted: $encrypted');
  print('encrypted (hex): ${hex.encode(encrypted)}');
  print('encrypted (base64): ${base64.encode(encrypted)}');
  print('decrypted: $decrypted');
  print('decrypted (hex): ${hex.encode(decrypted)}');
  print('decrypted (utf8): ${utf8.decode(decrypted)}');
}
```
