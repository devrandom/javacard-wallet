package org.gitian.javacard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;

public class HelloWorldApplet extends Applet {
    private static final byte[] helloWorld = {'H', 'e', 'l', 'l', 'o'};
    private static final byte HW_CLA = (byte) 0x80;
    private static final byte INS_PING = (byte) 0x00;
    private static final byte INS_TEST_SIGN = (byte) 0x01;
    private static final byte INS_TEST_PUB = (byte) 0x02;
    private static final byte INS_TEST_DERIVE = (byte) 0x03;
    private SECP256k1 secp256k1;

    private HelloWorldApplet() {
        secp256k1 = new SECP256k1();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HelloWorldApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte CLA = buffer[ISO7816.OFFSET_CLA];
        byte INS = buffer[ISO7816.OFFSET_INS];

        if (CLA != HW_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (INS == INS_PING) {
            getHelloWorld(apdu);
        } else if (INS == INS_TEST_SIGN) {
            testSign(apdu);
        } else if (INS == INS_TEST_PUB) {
            testPub(apdu);
        } else if (INS == INS_TEST_DERIVE) {
            testDerive(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private static final byte[] SECP256K1_PRIVATE = {
            (byte) 0xfb, (byte) 0x26, (byte) 0xa4, (byte) 0xe7, (byte) 0x5e, (byte) 0xec, (byte) 0x75, (byte) 0x54,
            (byte) 0x4c, (byte) 0x0f, (byte) 0x44, (byte) 0xe9, (byte) 0x37, (byte) 0xdc, (byte) 0xf5, (byte) 0xee,
            (byte) 0x63, (byte) 0x55, (byte) 0xc7, (byte) 0x17, (byte) 0x66, (byte) 0x00, (byte) 0xb9, (byte) 0x68,
            (byte) 0x8c, (byte) 0x66, (byte) 0x7e, (byte) 0x5c, (byte) 0x28, (byte) 0x3b, (byte) 0x43, (byte) 0xc5
    };

    private void testSign(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        ECPrivateKey privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        privateKey.setS(SECP256K1_PRIVATE, (short) 0, (short) SECP256K1_PRIVATE.length);
        secp256k1.setCurveParameters(privateKey);
        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        byte p1 = buffer[ISO7816.OFFSET_P1];

        for (short i = 1 ; i < p1 ; i++) {
            signature.init(privateKey, Signature.MODE_SIGN);
            short len = signature.signPreComputedHash(buffer, ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, buffer, (short) 0);
        }
    }

    private void testPub(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        ECPrivateKey privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        privateKey.setS(SECP256K1_PRIVATE, (short) 0, (short) SECP256K1_PRIVATE.length);
        secp256k1.setCurveParameters(privateKey);
        byte p1 = buffer[ISO7816.OFFSET_P1];
        for (short i = 1 ; i < p1 ; i++) {
            secp256k1.derivePublicKey(privateKey, buffer, (short) 0);
        }
    }

    private void testDerive(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Crypto crypto = new Crypto();
        byte[] derivationOutput = JCSystem.makeTransientByteArray((short) (Crypto.KEY_SECRET_SIZE + 32), JCSystem.CLEAR_ON_RESET);
        byte p1 = buffer[ISO7816.OFFSET_P1];
        //buffer[0] = (byte) 0x80;
        for (short i = 0; i < p1 ; i++) {
            crypto.bip32CKDPriv(buffer, (short) 0, buffer, (short) 1, buffer, (short) 38, derivationOutput, (short) 0);
        }
    }

    private void getHelloWorld(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) helloWorld.length;
        Util.arrayCopyNonAtomic(helloWorld, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }
}
