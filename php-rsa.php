<?php
// Caminho para os arquivos de chave privada e pública
$privateKeyPath = __DIR__ . '/private_key.pem';
$publicKeyPath = __DIR__ . '/public_key_teste.pem';

// Ler o conteúdo da chave privada e pública a partir dos arquivos
$privateKey = file_get_contents($privateKeyPath);
$publicKey = file_get_contents($publicKeyPath);

// Dados que serão assinados
$bodyData = [
    'transaction' => [
        'key' => '11111111111',
        'amount' => 2.11,
        'callback_url' => 'https://enu74s7tvngo.x.pipedream.net/',
        'external_id' => '12312312',
        'pixType' => 'CPF',
    ],
];

// Função para assinar dados usando uma chave privada
function signData($data, $privateKey) {
    // Converter os dados para uma string JSON
    $dataString = json_encode($data);

    // Criar um recurso de chave privada
    $privateKeyResource = openssl_pkey_get_private($privateKey);
    if (!$privateKeyResource) {
        throw new Exception('Falha ao obter chave privada');
    }

    // Assinar os dados usando a chave privada
    $signature = '';
    if (!openssl_sign($dataString, $signature, $privateKeyResource, OPENSSL_ALGO_SHA256)) {
        throw new Exception('Falha ao assinar os dados');
    }

    // Codificar a assinatura em base64
    $encodedSignature = base64_encode($signature);

    // Liberar o recurso da chave privada
    openssl_free_key($privateKeyResource);

    return $encodedSignature;
}

// Função para verificar a assinatura usando uma chave pública
function verifySignature($data, $signature, $publicKey) {
    // Converter os dados para uma string JSON
    $dataString = json_encode($data);

    // Criar um recurso de chave pública
    $publicKeyResource = openssl_pkey_get_public($publicKey);
    if (!$publicKeyResource) {
        throw new Exception('Falha ao obter chave pública');
    }

    // Verificar a assinatura usando a chave pública
    $decodedSignature = base64_decode($signature);
    $isVerified = openssl_verify($dataString, $decodedSignature, $publicKeyResource, OPENSSL_ALGO_SHA256);

    // Liberar o recurso da chave pública
    openssl_free_key($publicKeyResource);

    return $isVerified === 1;
}

// Assinar os dados
$encryptedData = signData($bodyData, $privateKey);

// Verificar a assinatura
$isValid = verifySignature($bodyData, $encryptedData, $publicKey);
echo 'isValid: ' . ($isValid ? 'true' : 'false') . PHP_EOL;
?>