<?php

use App\Http\Controllers\Api\VulnerabilityController;
use Illuminate\Support\Facades\Route;

Route::apiResource('vulnerabilities', VulnerabilityController::class);
