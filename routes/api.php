<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\VulnerabilityController;

Route::apiResource('vulnerabilities', VulnerabilityController::class);
