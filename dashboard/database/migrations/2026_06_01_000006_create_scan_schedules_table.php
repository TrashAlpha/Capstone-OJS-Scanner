<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scan_schedules', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();
            $table->string('name');
            $table->string('target_url');
            $table->string('scan_type', 50)->default('external');
            $table->string('admin_username')->nullable();
            $table->text('admin_password')->nullable(); // encrypted via model cast
            $table->string('frequency', 20)->default('daily'); // hourly|daily|weekly|monthly
            $table->string('cron_expression', 100);
            $table->string('timezone', 64)->default('UTC');
            $table->boolean('is_active')->default(true);
            $table->timestamp('last_run_at')->nullable();
            $table->timestamp('next_run_at')->nullable();
            $table->foreignId('last_scan_run_id')->nullable()->constrained('scan_runs')->nullOnDelete();
            $table->timestamps();

            $table->index(['is_active', 'next_run_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scan_schedules');
    }
};
