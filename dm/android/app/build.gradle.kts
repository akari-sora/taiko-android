plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    useLibrary("android.test.runner")
    useLibrary("android.test.base")
    useLibrary("android.test.mock")
    namespace = "org.d2rmobile.diagnostics"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    defaultConfig {
        applicationId = "org.taikocompat.android"
        testApplicationId = "org.taikocompat.android.test"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-taiko"
        ndk { abiFilters += "arm64-v8a" }
        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
    }
    externalNativeBuild {
        cmake {
            path = file("../native/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures { prefab = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.games:games-activity:4.4.2")
    // GameActivity's published artifact exposes AppCompatActivity as its base class.
    implementation("androidx.appcompat:appcompat:1.7.1")
}
