<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function getConnection(): ?string
    {
        return config('site-portrait.storage_connection');
    }

    public function up(): void
    {
        Schema::create('site_portrait_pairings', function (Blueprint $table) {
            $table->id();
            $table->string('status', 16)->index(); // pending | active
            $table->string('pairing_id', 64)->nullable()->unique();
            $table->json('service');
            $table->json('service_keys')->nullable();
            $table->json('scopes');
            $table->string('site_key_kid', 64);
            $table->string('site_key_public', 64);
            $table->text('site_key_secret'); // encrypted
            $table->json('site_key_endorsements')->nullable();
            $table->json('previous_site_keys')->nullable();
            $table->string('account_hint', 100)->nullable();
            // Pending pairing only.
            $table->string('callback_token_hash', 64)->nullable()->unique();
            $table->string('state_hash', 64)->nullable();
            $table->text('code_verifier')->nullable(); // encrypted
            $table->text('redirect_uri')->nullable();
            $table->timestamp('expires_at')->nullable();
            // Active pairing.
            $table->timestamp('connected_at')->nullable();
            $table->timestamp('confirmed_at')->nullable();
            $table->timestamp('keys_refreshed_at')->nullable();
            $table->timestamps();
        });

        Schema::create('site_portrait_nonces', function (Blueprint $table) {
            $table->id();
            $table->string('kid', 64);
            $table->string('nonce', 64);
            $table->timestamp('expires_at')->index();
            $table->unique(['kid', 'nonce']);
        });

        Schema::create('site_portrait_access_log', function (Blueprint $table) {
            $table->id();
            $table->timestamp('created_at')->index();
            $table->string('ip', 45)->nullable()->index();
            $table->string('method', 8);
            $table->string('endpoint', 32);
            $table->string('key_id', 64)->nullable();
            $table->json('scopes')->nullable();
            $table->unsignedSmallInteger('status');
            $table->string('error_code', 64)->nullable();
            $table->boolean('authenticated')->default(false)->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('site_portrait_access_log');
        Schema::dropIfExists('site_portrait_nonces');
        Schema::dropIfExists('site_portrait_pairings');
    }
};
