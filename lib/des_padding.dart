import 'package:dart_des/dart_des.dart';

class DESPadding {

  static List<int> pad(List<int> data, DESPaddingType paddingType) {
    if (paddingType == DESPaddingType.OneAndZeroes) {
      return _oneAndZerosPad(data);
    }

    return data;
  }

  static List<int> unpad(List<int> block, DESPaddingType paddingType) {
    if (paddingType == DESPaddingType.OneAndZeroes) {
      return _oneAndZerosUnpad(block);
    }

    return block;
  }

  /*
   * OneAndZeroes Padding
   *
   * For "OneAndZeroes" Padding add a byte of value 0x80 followed by as many
   * zero bytes as is necessary to fill the input to the next exact multiple
   * of B. Like PKCS5 padding, this method always adds padding of length
   * between one and B bytes to the input before encryption. It is easily
   * removed in an unambiguous manner after decryption.
   *
   * The "OneAndZeroes" term comes from the fact that this method appends a
   * 'one' bit to the input followed by as many 'zero' bits as is necessary.
   * The byte 0x80 is 10000000 in binary form. Note the spelling of
   * "Zeroes", which is what everyone else seems to use.
   *
   * Examples of OneAndZeroes padding for block length B = 8:
   *
   * 3 bytes: FDFDFD           --> FDFDFD8000000000
   * 7 bytes: FDFDFDFDFDFDFD   --> FDFDFDFDFDFDFD80
   * 8 bytes: FDFDFDFDFDFDFDFD --> FDFDFDFDFDFDFDFD8000000000000000
   */
  static List<int> _oneAndZerosPad(List<int> data) {
    final padding = [0x80] + List.generate(7, (index) => 0);
    int size = padding.length;
    int left = size - (data.length % size);
    return data + padding.sublist(0, left);
  }

  static List<int> _oneAndZerosUnpad(List<int> data) {
    List<int> reversed = List.from(data.reversed);
    int l = 0;
    while(reversed[l] == 0x00) {
      l += 1;
    }
    if (reversed[l] == 0x80) {
      return data.sublist(0, data.length - (l + 1));
    } else {
      return data;
    }
  }
}