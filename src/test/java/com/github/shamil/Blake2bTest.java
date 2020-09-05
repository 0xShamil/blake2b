package com.github.shamil;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;


class Blake2bTest {

    private static final String[][] keyedTestVectors =
            { // input/message, key, hash

                    // Vectors from BLAKE2 web site: https://blake2.net/blake2b-test.txt
                    {
                            "",
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"},

                    {
                            "00",
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                            "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd"},

                    {
                            "0001",
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                            "da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965"},

                    {
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d",
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                            "f1aa2b044f8f0c638a3f362e677b5d891d6fd2ab0765f6ee1e4987de057ead357883d9b405b9d609eea1b869d97fb16d9b51017c553f3b93c0a1e0f1296fedcd"},

                    {
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3",
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                            "c230f0802679cb33822ef8b3b21bf7a9a28942092901d7dac3760300831026cf354c9232df3e084d9903130c601f63c1f4a4a4b8106e468cd443bbe5a734f45f"},

                    {
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
                            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                            "142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"}};

    private final static String[][] unkeyedTestVectors =
            { // from: http://fossies.org/linux/john/src/rawBLAKE2_512_fmt_plug.c
                    // hash, input/message
                    // digests without leading $BLAKE2$
                    {
                            "4245af08b46fbb290222ab8a68613621d92ce78577152d712467742417ebc1153668f1c9e1ec1e152a32a9c242dc686d175e087906377f0c483c5be2cb68953e",
                            "blake2"},
                    {
                            "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0",
                            "hello world"},
                    {
                            "1f7d9b7c9a90f7bfc66e52b69f3b6c3befbd6aee11aac860e99347a495526f30c9e51f6b0db01c24825092a09dd1a15740f0ade8def87e60c15da487571bcef7",
                            "verystrongandlongpassword"},
                    {
                            "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
                            "The quick brown fox jumps over the lazy dog"},
                    {
                            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                            ""},
                    {
                            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                            "abc"},
            };

    public String getName() {
        return "BLAKE2b";
    }

    @Test
    void performTest() throws Exception {
        // test keyed test vectors:
        Blake2b blake2bKeyed = new Blake2b(decode(keyedTestVectors[0][1]));
        for (int tv = 0; tv < keyedTestVectors.length; tv++) {
            byte[] input = decode(keyedTestVectors[tv][0]);
            blake2bKeyed.reset();

            blake2bKeyed.update(input, 0, input.length);
            byte[] keyedHash = new byte[64];
            blake2bKeyed.doFinal(keyedHash, 0);

            assertArrayEquals(decode(keyedTestVectors[tv][2]), keyedHash);

            offsetTest(blake2bKeyed, input, keyedHash);
        }

        Blake2b blake2bUnkeyed = new Blake2b();
        // test unkeyed test vectors:
        for (int i = 0; i < unkeyedTestVectors.length; i++) {
            // blake2bunkeyed.update(
            // unkeyedTestVectors[i][1].getBytes("UTF-8"));
            // test update(byte b)
            byte[] unkeyedInput = unkeyedTestVectors[i][1].getBytes(StandardCharsets.UTF_8);
            for (int j = 0; j < unkeyedInput.length; j++) {
                blake2bUnkeyed.update(unkeyedInput[j]);
            }

            byte[] unkeyedHash = new byte[64];
            blake2bUnkeyed.doFinal(unkeyedHash, 0);
            blake2bUnkeyed.reset();

            assertArrayEquals(decode(unkeyedTestVectors[i][0]), unkeyedHash);
        }
    }

    private void offsetTest(Blake2b digest, byte[] input, byte[] expected) {
        byte[] resBuf = new byte[expected.length + 11];

        digest.update(input, 0, input.length);
        digest.doFinal(resBuf, 11);

        assertArrayEquals(Arrays.copyOfRange(resBuf, 11, resBuf.length), expected);
    }

    @Test
    void cloneTest() {
        Blake2b blake2bCloneSource = new Blake2b(
                decode(keyedTestVectors[3][1]),
                16,
                decode("000102030405060708090a0b0c0d0e0f"),
                decode("101112131415161718191a1b1c1d1e1f")
        );
        byte[] expected = decode("b6d48ed5771b17414c4e08bd8d8a3bc4");

        checkClone(blake2bCloneSource, expected);

        // just digest size
        blake2bCloneSource = new Blake2b(160);
        expected = decode("64202454e538279b21cea0f5a7688be656f8f484");
        checkClone(blake2bCloneSource, expected);

        // null salt and personalisation
        blake2bCloneSource = new Blake2b(decode(keyedTestVectors[3][1]), 16, null, null);
        expected = decode("2b4a081fae2d7b488f5eed7e83e42a20");
        checkClone(blake2bCloneSource, expected);

        // null personalisation
        blake2bCloneSource = new Blake2b(
                decode(keyedTestVectors[3][1]),
                16,
                decode("000102030405060708090a0b0c0d0e0f"), null);
        expected = decode("00c3a2a02fcb9f389857626e19d706f6");
        checkClone(blake2bCloneSource, expected);

        // null salt
        blake2bCloneSource = new Blake2b(
                decode(keyedTestVectors[3][1]),
                16,
                null,
                decode("101112131415161718191a1b1c1d1e1f")
        );
        expected = decode("f445ec9c062a3c724f8fdef824417abb");
        checkClone(blake2bCloneSource, expected);
    }

    private void checkClone(Blake2b blake2bCloneSource, byte[] expected) {
        byte[] message = decode(keyedTestVectors[3][0]);

        blake2bCloneSource.update(message, 0, message.length);

        byte[] hash = new byte[blake2bCloneSource.getDigestSize()];

        Blake2b digClone = new Blake2b(blake2bCloneSource);

        blake2bCloneSource.doFinal(hash, 0);
        assertArrayEquals(expected, hash);

        digClone.doFinal(hash, 0);

        assertArrayEquals(expected, hash);
    }

    @Test
    void testLengthConstruction() {
        Throwable lessThan8 = assertThrows(
                IllegalArgumentException.class,
                () -> new Blake2b(-1)
        );
        assertEquals("BLAKE2b digest bit length must be a multiple of 8 and not greater than 512", lessThan8.getMessage());

        Throwable greaterThan8 = assertThrows(
                IllegalArgumentException.class,
                () -> new Blake2b(9)
        );
        assertEquals("BLAKE2b digest bit length must be a multiple of 8 and not greater than 512", greaterThan8.getMessage());

        Throwable notMultipleOf8 = assertThrows(
                IllegalArgumentException.class,
                () -> new Blake2b(520)
        );
        assertEquals("BLAKE2b digest bit length must be a multiple of 8 and not greater than 512", notMultipleOf8.getMessage());

        Throwable invalidDigestLength = assertThrows(
                IllegalArgumentException.class,
                () -> new Blake2b(null, -1, null, null)
        );
        assertEquals("Invalid digest length (required: 1 - 64)", invalidDigestLength.getMessage());

        Throwable invalidDigestLengthGreaterThanZero = assertThrows(
                IllegalArgumentException.class,
                () -> new Blake2b(null, 65, null, null)
        );
        assertEquals("Invalid digest length (required: 1 - 64)", invalidDigestLengthGreaterThanZero.getMessage());
    }

    @Test
    void testNullKeyVsUnkeyed() {
        byte[] abc = "abc".getBytes();

        for (int i = 1; i != 64; i++) {
            Blake2b dig1 = new Blake2b(i * 8);
            Blake2b dig2 = new Blake2b(null, i, null, null);

            byte[] out1 = new byte[i];
            byte[] out2 = new byte[i];

            dig1.update(abc, 0, abc.length);
            dig2.update(abc, 0, abc.length);

            dig1.doFinal(out1, 0);
            dig2.doFinal(out2, 0);

            assertArrayEquals(out1, out2);
        }
    }

    @Test
    void resetTest() {
        // Generate a non-zero key
        byte[] key = new byte[32];
        for (byte i = 0; i < key.length; i++) {
            key[i] = i;
        }
        // Generate some non-zero input longer than the key
        byte[] input = new byte[key.length + 1];
        for (byte i = 0; i < input.length; i++) {
            input[i] = i;
        }
        // Hash the input
        Blake2b digest = new Blake2b(key);
        digest.update(input, 0, input.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        // Using a second instance, hash the input without calling doFinal()
        Blake2b digest1 = new Blake2b(key);
        digest1.update(input, 0, input.length);
        // Reset the second instance and hash the input again
        digest1.reset();
        digest1.update(input, 0, input.length);
        byte[] hash1 = new byte[digest.getDigestSize()];
        digest1.doFinal(hash1, 0);

        // The hashes should be identical
        assertArrayEquals(hash, hash1);
    }


    // hex utilities

    protected static final byte[] encodingTable = {
            (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6', (byte) '7',
            (byte) '8', (byte) '9', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'
    };

    /*
     * set up the decoding table.
     */
    protected static final byte[] decodingTable;

    static {
        decodingTable = new byte[128];
        for (int i = 0; i < decodingTable.length; i++) {
            decodingTable[i] = (byte) 0xff;
        }

        for (int i = 0; i < encodingTable.length; i++) {
            decodingTable[encodingTable[i]] = (byte) i;
        }

        decodingTable['A'] = decodingTable['a'];
        decodingTable['B'] = decodingTable['b'];
        decodingTable['C'] = decodingTable['c'];
        decodingTable['D'] = decodingTable['d'];
        decodingTable['E'] = decodingTable['e'];
        decodingTable['F'] = decodingTable['f'];
    }

    private static boolean ignore(char c) {
        return c == '\n' || c == '\r' || c == '\t' || c == ' ';
    }

    /**
     * decode the Hex encoded String data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public static int decode(String data, OutputStream out) throws IOException {
        byte b1, b2;
        int length = 0;
        byte[] buf = new byte[36];
        int bufOff = 0;

        int end = data.length();

        while (end > 0) {
            if (!ignore(data.charAt(end - 1))) {
                break;
            }

            end--;
        }

        int i = 0;
        while (i < end) {
            while (i < end && ignore(data.charAt(i))) {
                i++;
            }

            b1 = decodingTable[data.charAt(i++)];

            while (i < end && ignore(data.charAt(i))) {
                i++;
            }

            b2 = decodingTable[data.charAt(i++)];

            if ((b1 | b2) < 0) {
                throw new IOException("invalid characters encountered in Hex string");
            }

            buf[bufOff++] = (byte) ((b1 << 4) | b2);

            if (bufOff == buf.length) {
                out.write(buf);
                bufOff = 0;
            }

            length++;
        }

        if (bufOff > 0) {
            out.write(buf, 0, bufOff);
        }

        return length;
    }

    /**
     * decode the Hex encoded String data - whitespace will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static byte[] decode(String data) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try {
            decode(data, bOut);
        } catch (Exception e) {
            throw new RuntimeException("exception decoding Hex string: " + e.getMessage(), e);
        }

        return bOut.toByteArray();
    }

}