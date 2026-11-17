#!/usr/bin/env bash
# Auditoria do APK final, do lado de quem o descarrega: o que um atacante consegue ver sem código-fonte.
#   ANDROID_HOME=/caminho/do/sdk tools/auditar-apk.sh app/build/outputs/apk/release/app-release.apk
# Sai com erro se alguma verificação falhar. Precisa do aapt2 e do apksigner (build-tools 35) e do python3.
set -euo pipefail
APK="${1:?Uso: $0 ficheiro.apk}"
BT="${ANDROID_HOME:?Define ANDROID_HOME}/build-tools/35.0.0"
EXPECTED_CERT="2c4c4454ea600bde0046fdd6299f86ef8e528fcd5f78bfae54538c075187c394"
fails=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FALHA %s\n' "$1"; fails=$((fails + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
"$BT/aapt2" dump xmltree --file AndroidManifest.xml "$APK" > "$TMP/manifest.txt"
"$BT/aapt2" dump badging "$APK" > "$TMP/badging.txt"
unzip -Z1 "$APK" > "$TMP/files.txt"

echo "== Manifesto"
check "não é depurável (debuggable)" "! grep -q 'android:debuggable.*=true' '$TMP/manifest.txt'"
check "cópias de segurança desligadas (allowBackup=false)" "grep -q 'android:allowBackup.*=false' '$TMP/manifest.txt'"
check "regras de extração de dados presentes" "grep -q 'android:dataExtractionRules' '$TMP/manifest.txt'"
check "sem tráfego em claro (usesCleartextTraffic)" "! grep -q 'usesCleartextTraffic.*=true' '$TMP/manifest.txt'"
perms="$(grep -o "uses-permission: name='[^']*'" "$TMP/badging.txt" | sed "s/.*name='//;s/'//" | sort | tr '\n' ' ')"
echo "  permissões: $perms"
check "sem acesso à Internet" "! grep -q 'android.permission.INTERNET' <<< '$perms'"
extra="$(tr ' ' '\n' <<< "$perms" | grep -v -E '^$|HIDE_OVERLAY_WINDOWS|CAMERA|USE_BIOMETRIC|DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION' || true)"
check "só as permissões esperadas" "[ -z '$extra' ]"
python3 - "$TMP/manifest.txt" > "$TMP/exported.txt" <<'PY'
import re, sys
kind = None; name = None; exported = None; out = []
def flush():
    if kind and exported: out.append(f"{kind} {name}")
for line in open(sys.argv[1]):
    m = re.match(r"\s*E: (activity|service|receiver|provider|activity-alias) ", line)
    if m:
        flush(); kind, name, exported = m.group(1), None, False; continue
    if re.match(r"\s*E: ", line) and not re.match(r"\s*E: (intent-filter|action|category|data|meta-data)", line):
        flush(); kind = None
    if kind:
        n = re.search(r"android:name\(0x[0-9a-f]+\)=\"([^\"]+)\"", line)
        if n and name is None: name = n.group(1)
        if re.search(r"android:exported\(0x[0-9a-f]+\)=(true|\(type 0x12\)0xffffffff)", line): exported = True
flush()
print("\n".join(out))
PY
echo "  exportados: $(tr '\n' ' ' < "$TMP/exported.txt")"
check "só a atividade principal está aberta a outras apps" "[ \"\$(cat '$TMP/exported.txt')\" = 'activity app.reczi.pgp.MainActivity' ]"
check "atividade numa tarefa própria (taskAffinity vazio, contra StrandHogg)" "grep -q 'android:taskAffinity(0x01010012)=\"\"' '$TMP/manifest.txt'"
check "sem fornecedores de conteúdo nem serviços" "! grep -q -E 'E: (provider|service) ' '$TMP/manifest.txt'"

echo "== Assinatura"
"$BT/apksigner" verify --verbose --print-certs "$APK" > "$TMP/sig.txt" 2>&1 || true
check "assinatura válida" "grep -q '^Verifies' '$TMP/sig.txt'"
check "sem esquema v1 (JAR), que é fraco" "grep -q 'v1 scheme (JAR signing): false' '$TMP/sig.txt'"
check "esquema v2 ou v3" "grep -q -E 'v(2|3) scheme .*: true' '$TMP/sig.txt'"
cert="$(grep -m1 'certificate SHA-256 digest' "$TMP/sig.txt" | awk '{print $NF}')"
echo "  certificado: $cert"
check "certificado é o do Reczi cypher" "[ '$cert' = '$EXPECTED_CERT' ]"

echo "== Conteúdo"
check "sem bibliotecas nativas (lib/)" "! grep -q '^lib/' '$TMP/files.txt'"
check "sem chaves ou certificados soltos (.p12 .jks .keystore .pem .key)" "! grep -q -i -E '\.(p12|pfx|jks|keystore|bks|pem|key)$' '$TMP/files.txt'"
check "sem configuração de serviços na cloud (google-services, firebase)" "! grep -q -i -E 'google-services|firebase|crashlytics' '$TMP/files.txt'"
mkdir "$TMP/x"; unzip -q -o "$APK" 'classes*.dex' -d "$TMP/x"
cat "$TMP"/x/classes*.dex > "$TMP/all.dex"
check "sem bibliotecas de testes (junit, robolectric, mockito)" "! grep -a -q -E 'org/junit/|org/robolectric/|org/mockito/' '$TMP/all.dex'"
check "sem bibliotecas de rede, anúncios ou estatísticas (okhttp, retrofit, firebase, analytics)" "! grep -a -q -i -E 'okhttp3/|retrofit2/|com/google/firebase|com/google/android/gms/(ads|analytics)|io/sentry|com/facebook/' '$TMP/all.dex'"
check "sem chaves privadas embutidas" "! grep -a -q -E -- '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=]' '$TMP/all.dex'"
check "sem a palavra-passe da chave de assinatura (storePassword/RECZI_STORE_PASSWORD)" "! grep -a -q -E 'RECZI_STORE_PASSWORD|storePassword' '$TMP/all.dex'"
check "sem registos no logcat (android.util.Log não é usado)" "! grep -a -q 'Landroid/util/Log;' '$TMP/all.dex'"

echo
if [ "$fails" -eq 0 ]; then echo "Tudo bem: $(basename "$APK")"; else echo "$fails verificação(ões) falharam"; exit 1; fi
