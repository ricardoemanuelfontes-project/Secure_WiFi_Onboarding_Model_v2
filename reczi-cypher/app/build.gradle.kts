import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "app.reczi.pgp"
    compileSdk = 35

    defaultConfig {
        // O id interno continua "app.reczi.pgp" (só o nome visível mudou para "Reczi cypher"):
        // assim esta versão instala-se por cima da anterior e as chaves guardadas mantêm-se.
        applicationId = "app.reczi.pgp"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "1.2"
    }

    // Chave de assinatura da app, FORA do projeto (nunca vai para um repositório):
    //   ficheiro: ../reczi-signing/reczi-release.p12 (ou -Preczi.storeFile=<caminho>)
    //   palavra-passe: reczi.storePassword em ~/.gradle/gradle.properties (ou RECZI_STORE_PASSWORD)
    // Guarda-a: as atualizações da app têm de ser assinadas com a mesma chave.
    val storeFile = providers.gradleProperty("reczi.storeFile").map { rootProject.file(it) }
        .getOrElse(rootProject.file("../reczi-signing/reczi-release.p12"))
    val storePassword = providers.gradleProperty("reczi.storePassword")
        .orElse(providers.environmentVariable("RECZI_STORE_PASSWORD")).orNull
    val canSign = storeFile.exists() && storePassword != null
    if (canSign) {
        signingConfigs {
            create("release") {
                this.storeFile = storeFile
                this.storePassword = storePassword
                keyAlias = "reczi"
                keyPassword = storePassword
            }
        }
    }
    // Nunca produzir em silêncio um APK de release sem assinatura.
    gradle.taskGraph.whenReady {
        if (!canSign && allTasks.any { it.project == project && it.name.contains("Release") }) {
            throw GradleException("Falta a chave de assinatura: $storeFile e/ou reczi.storePassword.")
        }
    }

    buildTypes {
        release {
            // Sem R8: o BouncyCastle usa reflexão e a app é pequena.
            isMinifyEnabled = false
            if (canSign) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/BCKEY.DSA", "META-INF/BCKEY.SF", "META-INF/BC1024KE.DSA", "META-INF/BC1024KE.SF",
                "META-INF/BC2048KE.DSA", "META-INF/BC2048KE.SF",
                "META-INF/DEPENDENCIES", "META-INF/LICENSE*", "META-INF/NOTICE*",
            )
        }
    }

    dependenciesInfo {
        // Não incluir no APK o bloco de metadados de dependências cifrado para a Google.
        includeInApk = false
        includeInBundle = false
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    implementation("app.reczi.pgp:core:1.0")
}
