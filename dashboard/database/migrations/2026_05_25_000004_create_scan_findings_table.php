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
        Schema::create('scan_findings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_run_id')->constrained()->cascadeOnDelete();
            $table->string('target');
            $table->string('type', 50);
            $table->string('category')->nullable();
            $table->string('finding');
            $table->decimal('cvss_score', 4, 1)->default(0);
            $table->string('risk', 50)->default('informational');
            $table->timestamp('scanned_at');
            $table->longText('evidence')->nullable();
            $table->string('cwe_id', 50)->nullable();
            $table->text('cvss_vector')->nullable();
            $table->timestamps();

            $table->index(['risk', 'type']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_findings');
    }
};
