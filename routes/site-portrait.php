<?php

use Ctrlweb\SitePortrait\Http\Controllers\PairingCallbackController;
use Ctrlweb\SitePortrait\Http\Controllers\PortraitController;
use Ctrlweb\SitePortrait\Http\Controllers\RevokeController;
use Ctrlweb\SitePortrait\Http\Controllers\StatusController;
use Ctrlweb\SitePortrait\Http\Middleware\HandleSitePortraitRequest;
use Illuminate\Support\Facades\Route;

// Signed API: no session, no CSRF, no framework throttle; our middleware only.
Route::group([
    'prefix' => trim((string) config('site-portrait.route_prefix'), '/'),
    'domain' => config('site-portrait.route_domain'),
    'middleware' => [HandleSitePortraitRequest::class],
], function () {
    Route::get('status', StatusController::class)->name('site-portrait.status');
    Route::get('portrait', PortraitController::class)->name('site-portrait.portrait');
    Route::post('revoke', RevokeController::class)->name('site-portrait.revoke');
});

Route::get(trim((string) config('site-portrait.callback_path'), '/'), PairingCallbackController::class)
    ->middleware((array) config('site-portrait.callback_middleware', []))
    ->name('site-portrait.callback');
