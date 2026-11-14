pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "reczi-cypher"
// Núcleo de criptografia: build independente (testes JVM), usado pela app como dependência.
includeBuild("core")
include(":app")
