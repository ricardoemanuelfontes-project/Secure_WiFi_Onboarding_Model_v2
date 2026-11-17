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

/**
 * O desfazedor de disfarce para o computador, num só ficheiro com tudo o que precisa:
 *   ./gradlew :core:desfazerJar   ->   core/build/libs/reczi-desfazer.jar
 *   java -jar reczi-desfazer.jar mensagem.txt | gpg --decrypt
 */
tasks.register<Jar>("desfazerJar") {
    archiveFileName = "reczi-desfazer.jar"
    manifest { attributes("Main-Class" to "app.reczi.pgp.core.Desfazer") }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({ configurations.runtimeClasspath.get().filter { it.name.endsWith(".jar") }.map { zipTree(it) } })
    // As assinaturas dos jars das bibliotecas deixam de valer depois de os juntar.
    exclude("META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA", "META-INF/*.EC", "META-INF/versions/*/module-info.class", "module-info.class")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
