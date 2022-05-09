import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:dart_des/dart_des.dart';

main() {
  String key = '12345678'; // 8-byte
  String message = 'Driving in from the edge of to';
  List<int> encrypted;
  List<int> decrypted;
  List<int> iv = [1, 2, 3, 4, 5, 6, 7, 8];

  print('key: $key');
  print('message: $message');

  DES desECBPKCS5 = DES(
    key: key.codeUnits,
    mode: DESMode.ECB,
    paddingType: DESPaddingType.PKCS5,
  );
  encrypted = desECBPKCS5.encrypt(message.codeUnits);
  decrypted = desECBPKCS5.decrypt(encrypted);
  print('DES mode: ECB');
  // print('encrypted: $encrypted');
  print('encrypted (hex): ${hex.encode(encrypted)}');
  print('encrypted (base64): ${base64.encode(encrypted)}');
  // print('decrypted: $decrypted');
  print('decrypted (hex): ${hex.encode(decrypted)}');
  print('decrypted (utf8): ${utf8.decode(decrypted)}');

  DES desECB = DES(key: key.codeUnits, mode: DESMode.ECB);
  encrypted = desECB.encrypt(message.codeUnits);
  decrypted = desECB.decrypt(encrypted);
  print('DES mode: ECB');
  // print('encrypted: $encrypted');
  print('encrypted (hex): ${hex.encode(encrypted)}');
  print('encrypted (base64): ${base64.encode(encrypted)}');
  // print('decrypted: $decrypted');
  print('decrypted (hex): ${hex.encode(decrypted)}');
  print('decrypted (utf8): ${utf8.decode(decrypted)}');

  DES desCBC = DES(key: key.codeUnits, mode: DESMode.CBC, iv: iv);
  encrypted = desCBC.encrypt(message.codeUnits);
  decrypted = desCBC.decrypt(encrypted);
  print('DES mode: CBC');
  // print('encrypted: $encrypted');
  print('encrypted (hex): ${hex.encode(encrypted)}');
  print('encrypted (base64): ${base64.encode(encrypted)}');
  // print('decrypted: $decrypted');
  print('decrypted (hex): ${hex.encode(decrypted)}');
  print('decrypted (utf8): ${utf8.decode(decrypted)}');

  key = '1234567812345678'; // 16-byte
  DES3 des3ECB = DES3(key: key.codeUnits, mode: DESMode.ECB);
  encrypted = des3ECB.encrypt(message.codeUnits);
  decrypted = des3ECB.decrypt(encrypted);
  print('Triple DES mode: ECB');
  // print('encrypted: $encrypted');
  print('encrypted (hex): ${hex.encode(encrypted)}');
  print('encrypted (base64): ${base64.encode(encrypted)}');
  // print('decrypted: $decrypted');
  print('decrypted (hex): ${hex.encode(decrypted)}');
  print('decrypted (utf8): ${utf8.decode(decrypted)}');

  key = '123456781234567812345678'; // 24-byte
  DES3 des3CBC = DES3(key: key.codeUnits, mode: DESMode.CBC, iv: iv);
  encrypted = des3CBC.encrypt(message.codeUnits);
  decrypted = des3CBC.decrypt(encrypted);
  print('Triple DES mode: CBC');
  // print('encrypted: $encrypted');
  print('encrypted (hex): ${hex.encode(encrypted)}');
  print('encrypted (base64): ${base64.encode(encrypted)}');
  // print('decrypted: $decrypted');
  print('decrypted (hex): ${hex.encode(decrypted)}');
  print('decrypted (utf8): ${utf8.decode(decrypted)}');
}
