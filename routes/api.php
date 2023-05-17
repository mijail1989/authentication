<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthenticationController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
Route::post('/login', [AuthenticationController::class, 'login'])->name('login');
Route::post('/register', [AuthenticationController::class, 'register'])->name('register');  
Route::middleware('auth:sanctum')->post('/logout', [AuthenticationController::class, 'logout'])->name('logout');
Route::middleware('auth:sanctum')->get('/esempio', [AuthenticationController::class, 'esempio']);