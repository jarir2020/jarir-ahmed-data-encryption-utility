<?php

namespace JarirAhmed\Encryptor\Tests;

use JarirAhmed\Encryptor\Encryptor;
use PHPUnit\Framework\TestCase;

class EncryptorTest extends TestCase
{
    public function testGcmRoundTrip()
    {
        $e = new Encryptor('secret-key');
        $plain = 'Hello, world! 12345';
        $this->assertSame($plain, $e->decrypt($e->encrypt($plain)));
    }

    public function testCbcRoundTripWithHmac()
    {
        $e = new Encryptor('secret-key', 'aes-256-cbc');
        $plain = 'sensitive payload';
        $this->assertSame($plain, $e->decrypt($e->encrypt($plain)));
    }

    public function testEmptyStringRoundTrips()
    {
        $e = new Encryptor('k');
        $this->assertSame('', $e->decrypt($e->encrypt('')));
    }

    public function testCiphertextsAreNonDeterministic()
    {
        $e = new Encryptor('k');
        $this->assertNotSame($e->encrypt('same'), $e->encrypt('same'));
    }

    public function testTamperedGcmCiphertextRejected()
    {
        $e = new Encryptor('k');
        $ct = base64_decode($e->encrypt('data'));
        $ct[strlen($ct) - 1] = $ct[strlen($ct) - 1] === 'A' ? 'B' : 'A';
        $this->expectException(\RuntimeException::class);
        $e->decrypt(base64_encode($ct));
    }

    public function testTamperedCbcCiphertextRejectedByHmac()
    {
        $e = new Encryptor('k', 'aes-256-cbc');
        $ct = base64_decode($e->encrypt('data'));
        $ct[strlen($ct) - 1] = $ct[strlen($ct) - 1] === 'A' ? 'B' : 'A';
        $this->expectException(\RuntimeException::class);
        $e->decrypt(base64_encode($ct));
    }

    public function testWrongKeyFails()
    {
        $ct = (new Encryptor('right'))->encrypt('data');
        $this->expectException(\RuntimeException::class);
        (new Encryptor('wrong'))->decrypt($ct);
    }

    public function testEmptyKeyRejected()
    {
        $this->expectException(\InvalidArgumentException::class);
        new Encryptor('');
    }

    public function testUnsupportedCipherRejected()
    {
        $this->expectException(\InvalidArgumentException::class);
        new Encryptor('k', 'not-a-cipher');
    }
}
