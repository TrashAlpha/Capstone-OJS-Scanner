<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('scan_runs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();
            $table->string('target_url');
            $table->string('scan_type', 50);
            $table->string('status', 50)->default('completed');
            $table->unsignedInteger('summary_total_findings')->default(0);
            $table->decimal('summary_max_score', 4, 1)->default(0);
            $table->string('summary_severity', 50)->default('INFORMATIONAL');
            $table->json('warnings')->nullable();
            $table->json('scanner_payload')->nullable();
            $table->json('risk_payload')->nullable();
            $table->timestamp('scanned_at');
            $table->timestamps();

            $table->index(['target_url', 'scanned_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_runs');
    }
};
