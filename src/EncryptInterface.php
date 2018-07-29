<?php

namespace VS\Encrypt;

/**
 * Interface EncryptInterface
 * @package VS\Encrypt
 * @author Varazdat Stepanyan
 */
interface EncryptInterface
{
    /**
     * @param string $content
     * @return string
     */
    public function encrypt(string $content): string;

    /**
     * @param string $encryptedContent
     * @return string
     */
    public function decrypt(string $encryptedContent): string;
}