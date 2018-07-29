<?php

namespace Core\Security\Strategy;

use VS\Encrypt\EncryptInterface;

/**
 * Class Base64OpenSSL
 * @package Core\Security\Strategy
 */
class Base64OpenSSL implements EncryptInterface
{
    /**
     * @var string $key
     */
    protected $key;
    /**
     * @var string $algorithm
     */
    protected $algorithm;

    /**
     * Base64OpenSSLStrategy constructor.
     * @param string $key
     * @param string $algorithm
     */
    public function __construct(string $key, string $algorithm = 'AES-256-CBC')
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
    }

    /**
     * @param mixed $data
     * @return string
     */
    public function encrypt($data): string
    {
        $salt = openssl_random_pseudo_bytes(16);

        $salted = '';
        $dx = '';

        while (strlen($salted) < 48) {
            $dx = hash('sha256', $dx . $this->key . $salt, true);
            $salted .= $dx;
        }

        $key = substr($salted, 0, 32);
        $iv = substr($salted, 32, 16);

        $encryptedData = openssl_encrypt($data, $this->algorithm, $key, true, $iv);
        return base64_encode($salt . $encryptedData);
    }

    /**
     * @param string $encryptedData
     * @return string
     */
    public function decrypt(string $encryptedData): string
    {
        $data = base64_decode($encryptedData);
        $salt = substr($data, 0, 16);
        $ct = substr($data, 16);

        $rounds = 3;
        $passwordSalt = $this->key . $salt;
        $hash = [hash('sha256', $passwordSalt, true)];
        $result = $hash[0];
        for ($i = 1; $i < $rounds; $i++) {
            $hash[$i] = hash('sha256', $hash[$i - 1] . $passwordSalt, true);
            $result .= $hash[$i];
        }
        $key = substr($result, 0, 32);
        $iv = substr($result, 32, 16);

        return openssl_decrypt($ct, $this->algorithm, $key, true, $iv);
    }
}