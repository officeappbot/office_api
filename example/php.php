<?php


$secret = 'SECRET-KEY';
$public = 'PUBLIC-KEY';


//Шаг №1. Необходимо получить фразу
$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => 'https://rest-api.officebot.app/api/get-phrase',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_HTTPHEADER => array(
        'Accept: application/json'
    ),
));

$response = curl_exec($curl);

curl_close($curl);


$result = json_decode($response, true);
if (isset($result['data']['phrase'])) {

    //Шаг №2. Добавить к полученной фразе | и текущее время
    $phrase =  $result['data']['phrase'] . '|' . time();

    //Шаг №3. Зашифровать фразу секретным ключом
    $enc = (new ChaCha20EncryptDecrypt($secret))->encrypt($phrase);

    //Шаг №4. Создать финальный токен, который состоит из публичного ключа + | + результат шифрования
    $finalToken = $public . '|' . $enc;
    echo ($finalToken);
} else {
    echo 'no phrase';
}




class ChaCha20EncryptDecrypt
{
    private string $key;
    private string $nonce;

    public function __construct(string $key)
    {
        $this->key = sodium_crypto_generichash($key, '', 32);
        $this->nonce = random_bytes(SODIUM_CRYPTO_STREAM_NONCEBYTES);
    }

    public function encrypt(string $data): string
    {
        $ciphertext = sodium_crypto_stream_xor($data, $this->nonce, $this->key);
        return base64_encode($this->nonce . $ciphertext);
    }

    public function decrypt(string $data): string
    {
        $decoded = base64_decode($data);
        $nonce = substr($decoded, 0, SODIUM_CRYPTO_STREAM_NONCEBYTES);
        $ciphertext = substr($decoded, SODIUM_CRYPTO_STREAM_NONCEBYTES);
        return sodium_crypto_stream_xor($ciphertext, $nonce, $this->key);
    }
}
