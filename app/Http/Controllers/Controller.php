<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Laravel\Lumen\Routing\Controller as BaseController;

class Controller extends BaseController
{
    
    public function index(Request $request): JsonResponse
    {
        $this->validateData($request);
        $response = $this->sendRequest(
            $this->getParam($request, 'method'),
            $this->getUrl($request),
            $this->getParam($request, 'body'),
            $this->handleHeader($request)
        );
        return $response['status'] == 400
            ? response()->json(['error' => $response['error']], $response['status'])
            : response()->json($response, 200);        
    }

    private function sendRequest(String $method, String $url, String $jsonData, array $headers): array
    {
        $curl = curl_init();

        curl_setopt_array($curl, array(
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_POSTFIELDS => $jsonData,
            CURLOPT_HTTPHEADER => $this->convertArrayToHeader($headers),
            CURLOPT_ENCODING => '',
            CURLOPT_RETURNTRANSFER => true
        ));

        $response = curl_exec($curl);
        $error = curl_error($curl);

        
        curl_close($curl);
        
        if ($error) {
            return ['error' => $error, 'status' => 400];
        }
        return json_decode($response, true);
    }

    private function validateData(Request $request): void
    {
        $this->validate($request, [
            'method' => 'required',
            'protocol' => 'required',
            'key' => 'required',
            'uri' => 'required',
            'controller' => 'required',
            'action' => 'required'
        ]);
    }

    private function getURL(Request $request): String
    {
        return $this->getParam($request, 'protocol') . '://' . 
               $this->getParam($request, 'uri') . '/' .  
               $this->getParam($request, 'controller') . '/' . 
               $this->getParam($request, 'action');
    }

    private function getParam(Request $request, String $field): String
    {
        $field =  $request->only([$field])[$field];
        if (is_array($field)) {
            return json_encode($field);
        }
        return $field;
    }

    private function handleHeader(Request $request): array
    {
        $hmacData = $this->handleHMAC($request);
        $version = 1;
        $key = $hmacData['key'];
        $nonce = $hmacData['nonce'];
        $hmac = $hmacData['hmac'];
        return [
            'Content-Type' => 'application/json',
            'HMAC-Authentication' => "$version:$key:$nonce:$hmac"
        ];
    }

    private function handleHMAC(Request $request): array
    {
        $key = $this->getParam($request, 'key');
        $method = $this->getParam($request, 'method');
        $data = $this->getParam($request, 'body');
        $url = $this->getUrl($request);
        $nonce = time();
        $secretKey = $nonce . $key;
        $signature = $method . $url . $data;
        $hmac = $this->createHmac($secretKey, $signature);
        return [
            'key' => $secretKey,
            'nonce' => $nonce,
            'hmac' => $hmac,
        ];
    }
        
    private function createHmac(String $key, String $signature): String
    {
        $algorithm = 'sha256';
        return hash(
            $algorithm,
            hash($algorithm, $key) .  hash($algorithm, $key  . $signature)
        );
    }

    private function convertArrayToHeader(array $array): array
    {
        return array_map(function ($k, $v) {
            return "$k: $v";
        }, array_keys($array), array_values($array));
    }
}
