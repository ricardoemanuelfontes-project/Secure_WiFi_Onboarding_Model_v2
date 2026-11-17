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
        versionCode = 12
        versionName = "1.4.6"
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
        // Versão de teste: outro identificador e outro nome, para ficar instalada ao lado da
        // verdadeira sem a substituir (e sem tocar nas chaves que lá estão).
        debug {
            applicationIdSuffix = ".teste"
            versionNameSuffix = "-teste"
            manifestPlaceholders["appLabel"] = "Reczi teste"
        }
        release {
            manifestPlaceholders["appLabel"] = "Reczi cypher"
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

    testOptions {
        // Testes da interface no computador (Robolectric), sem telemóvel nem emulador.
        unitTests.isIncludeAndroidResources = true
        unitTests.all { it.maxHeapSize = "2g" }
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
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
}
