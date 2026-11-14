import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.1.21"
}

group = "app.reczi.pgp"
version = "1.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    api("org.pgpainless:pgpainless-core:1.7.8")
    // Códigos QR (gerar e ler): Java puro, sem Android nem rede.
    api("com.google.zxing:core:3.5.3")
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}
