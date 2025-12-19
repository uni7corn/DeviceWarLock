package com.xiaoc.warlock.Core.detector;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Android Bootloader状态检测工具类
 * 使用密钥认证(Key Attestation)检测设备bootloader解锁状态
 */
public class BootloaderStateChecker {
    private static final String TAG = "BootloaderDetector";
    private static final String KEY_ALIAS = "bootloader_check_key";
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    // 超时设置（秒）
    private static final int DEFAULT_TIMEOUT_SECONDS = 10;

    // 启动验证状态
    public static final int VERIFIED_BOOT_VERIFIED = 0;     // 设备处于完全锁定和验证状态
    public static final int VERIFIED_BOOT_SELF_SIGNED = 1;  // 设备使用自签名的引导镜像启动
    public static final int VERIFIED_BOOT_UNVERIFIED = 2;   // 设备以未验证的状态启动
    public static final int VERIFIED_BOOT_FAILED = 3;       // 设备启动验证失败

    /**
     * Bootloader状态结果
     */
    public enum BootloaderStatus {
        LOCKED("LOCKED", true),
        UNLOCKED("UNLOCKED", false),
        LOCKED_INSECURE("LOCKED_INSECURE", false),
        UNKNOWN("UNKNOWN", false);

        private final String displayName;
        private final boolean secure;

        BootloaderStatus(String displayName, boolean secure) {
            this.displayName = displayName;
            this.secure = secure;
        }

        public String getDisplayName() {
            return displayName;
        }

        public boolean isSecure() {
            return secure;
        }
    }

    static {
        // 初始化BouncyCastle
        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (Exception e) {
            Log.e(TAG, "无法初始化BouncyCastle", e);
        }
    }

    /**
     * 检测设备bootloader状态
     *
     * @param context 应用上下文
     * @return bootloader状态
     */
    public static BootloaderStatus detectStatus(Context context) {
        return detectStatus(context, DEFAULT_TIMEOUT_SECONDS);
    }

    /**
     * 检测设备bootloader状态（带超时）
     *
     * @param context 应用上下文
     * @param timeoutSeconds 超时时间（秒）
     * @return bootloader状态
     */
    public static BootloaderStatus detectStatus(Context context, int timeoutSeconds) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            Log.w(TAG, "设备API级别过低，不支持密钥认证");
            return BootloaderStatus.UNKNOWN;
        }

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<BootloaderStatus> future = executor.submit(new BootloaderStatusTask(context));

        try {
            return future.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            Log.e(TAG, "检测bootloader状态时出错", e);
            return BootloaderStatus.UNKNOWN;
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * 后台执行bootloader状态检测的任务
     */
    private static class BootloaderStatusTask implements Callable<BootloaderStatus> {
        private final Context context;

        BootloaderStatusTask(Context context) {
            this.context = context;
        }

        @Override
        public BootloaderStatus call() {
            try {
                // 第一步：通过Key Attestation检测，尝试使用StrongBox
                BootloaderStatus strongBoxResult = checkWithStrongBox();
                if (strongBoxResult != BootloaderStatus.UNKNOWN) {
                    Log.d(TAG, "使用StrongBox成功检测到bootloader状态: " + strongBoxResult);
                    return strongBoxResult;
                }

                // 如果StrongBox失败，尝试使用标准KeyStore
                BootloaderStatus standardResult = checkWithoutStrongBox();
                if (standardResult != BootloaderStatus.UNKNOWN) {
                    Log.d(TAG, "使用标准KeyStore成功检测到bootloader状态: " + standardResult);
                    return standardResult;
                }

                // 如果两种方法都失败，尝试证书内容分析作为补充方法
                BootloaderStatus certificateResult = checkViaCertificateContent();
                if (certificateResult != BootloaderStatus.UNKNOWN) {
                    Log.d(TAG, "通过证书内容分析成功检测到bootloader状态: " + certificateResult);
                    return certificateResult;
                }

                Log.w(TAG, "所有检测方法均失败，无法确定bootloader状态");
                return BootloaderStatus.UNKNOWN;
            } catch (Exception e) {
                Log.e(TAG, "检测过程中出错", e);
                return BootloaderStatus.UNKNOWN;
            }
        }

        /**
         * 使用StrongBox进行检测
         */
        private BootloaderStatus checkWithStrongBox() {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                Log.d(TAG, "设备API级别过低，不支持StrongBox");
                return BootloaderStatus.UNKNOWN;
            }

            try {
                Log.d(TAG, "使用StrongBox开始检测");
                // 生成密钥并获取证书链
                generateKeyWithStrongBox();
                X509Certificate[] certChain = getAttestationCertificateChain();

                if (certChain == null || certChain.length == 0) {
                    Log.w(TAG, "无法获取StrongBox证书链");
                    return BootloaderStatus.UNKNOWN;
                }

                // 从证书中解析Root of Trust信息
                return analyzeRootOfTrust(certChain);
            } catch (Exception e) {
                Log.e(TAG, "使用StrongBox检测时出错: " + e.getMessage());
                return BootloaderStatus.UNKNOWN;
            }
        }

        /**
         * 使用标准KeyStore检测
         */
        private BootloaderStatus checkWithoutStrongBox() {
            try {
                Log.d(TAG, "使用标准KeyStore开始检测");
                // 生成密钥并获取证书链
                generateKeyWithoutStrongBox();
                X509Certificate[] certChain = getAttestationCertificateChain();

                if (certChain == null || certChain.length == 0) {
                    Log.w(TAG, "无法获取标准KeyStore证书链");
                    return BootloaderStatus.UNKNOWN;
                }

                // 从证书中解析Root of Trust信息
                return analyzeRootOfTrust(certChain);
            } catch (Exception e) {
                Log.e(TAG, "使用标准KeyStore检测时出错: " + e.getMessage());
                return BootloaderStatus.UNKNOWN;
            }
        }

        /**
         * 分析证书中的Root of Trust信息
         */
        private BootloaderStatus analyzeRootOfTrust(X509Certificate[] certChain) {
            for (X509Certificate cert : certChain) {
                RootOfTrust rootOfTrust = extractRootOfTrust(cert);
                if (rootOfTrust != null) {
                    // 基于Root of Trust信息判断bootloader状态
                    if (!rootOfTrust.isDeviceLocked()) {
                        return BootloaderStatus.UNLOCKED;
                    } else if (rootOfTrust.getVerifiedBootState() != VERIFIED_BOOT_VERIFIED) {
                        return BootloaderStatus.LOCKED_INSECURE;
                    } else {
                        return BootloaderStatus.LOCKED;
                    }
                }
            }

            Log.w(TAG, "在证书链中未找到Root of Trust信息");
            return BootloaderStatus.UNKNOWN;
        }

        /**
         * 通过证书内容分析间接判断
         * 针对不在证书中包含Root of Trust的设备
         */
        private BootloaderStatus checkViaCertificateContent() {
            try {
                X509Certificate[] certChain = getAttestationCertificateChain();
                if (certChain == null || certChain.length == 0) {
                    return BootloaderStatus.UNKNOWN;
                }

                // 检查证书内容中的特征
                for (X509Certificate cert : certChain) {
                    String certSubject = cert.getSubjectX500Principal().getName();
                    String certIssuer = cert.getIssuerX500Principal().getName();

                    // 检查证书内容中是否包含特定字符串
                    if (containsUnlockedIndicator(cert)) {
                        return BootloaderStatus.UNLOCKED;
                    }

                    // 检查是否有自签名证书（通常表示设备被修改）
                    if (certSubject.equals(certIssuer) && !isTrustedIssuer(certSubject)) {
                        // 自签名且非信任发行者通常表示设备已解锁
                        return BootloaderStatus.UNLOCKED;
                    }

                    // 检查是否有可信证书链（通常表示设备未解锁）
                    if (hasValidManufacturerChain(certChain)) {
                        return BootloaderStatus.LOCKED;
                    }
                }

                return BootloaderStatus.UNKNOWN;
            } catch (Exception e) {
                Log.e(TAG, "通过证书内容检测时出错", e);
                return BootloaderStatus.UNKNOWN;
            }
        }

        /**
         * 检查证书中是否包含解锁指示器
         */
        private boolean containsUnlockedIndicator(X509Certificate cert) {
            try {
                // 检查常见的解锁相关字符串
                String[] unlockIndicators = {
                        "unlocked", "debuggable", "test-keys", "dev-keys", "insecure"
                };

                String certString = cert.toString().toLowerCase();
                for (String indicator : unlockIndicators) {
                    if (certString.contains(indicator)) {
                        return true;
                    }
                }

                return false;
            } catch (Exception e) {
                return false;
            }
        }

        /**
         * 检查是否为信任的证书发行者
         */
        private boolean isTrustedIssuer(String issuer) {
            // 检查是否为知名的证书发行者
            String[] trustedIssuers = {
                    "google", "android", "qualcomm", "mediatek", "samsung", "xiaomi", "huawei", "oppo", "vivo"
            };

            String lowerIssuer = issuer.toLowerCase();
            for (String trusted : trustedIssuers) {
                if (lowerIssuer.contains(trusted)) {
                    return true;
                }
            }

            return false;
        }

        /**
         * 检查是否有有效的制造商证书链
         */
        private boolean hasValidManufacturerChain(X509Certificate[] certChain) {
            if (certChain == null || certChain.length < 2) {
                return false;
            }

            // 检查证书链中是否包含制造商证书
            for (X509Certificate cert : certChain) {
                String issuer = cert.getIssuerX500Principal().getName().toLowerCase();
                if (issuer.contains("google") || issuer.contains("android") ||
                        issuer.contains("qualcomm") || issuer.contains("mediatek") ||
                        issuer.contains(Build.MANUFACTURER.toLowerCase())) {
                    return true;
                }
            }

            return false;
        }
    }

    /**
     * 使用StrongBox生成带有认证信息的密钥对
     */
    private static void generateKeyWithStrongBox() throws Exception {
        // 清除可能存在的旧密钥
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS);
        }

        // 创建认证挑战（确保每次不同）
        byte[] challenge = new Date().toString().getBytes();

        // 配置密钥生成参数
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);

        // 明确使用StrongBox
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true);
        } else {
            throw new IllegalStateException("设备不支持StrongBox");
        }

        // 生成密钥对
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        generator.initialize(builder.build());
        generator.generateKeyPair();
        Log.d(TAG, "使用StrongBox成功生成密钥");
    }

    /**
     * 使用标准KeyStore生成带有认证信息的密钥对
     */
    private static void generateKeyWithoutStrongBox() throws Exception {
        // 清除可能存在的旧密钥
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS);
        }

        // 创建认证挑战（确保每次不同）
        byte[] challenge = new Date().toString().getBytes();

        // 配置密钥生成参数
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);

        // 明确不使用StrongBox
        // 生成密钥对
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        generator.initialize(builder.build());
        generator.generateKeyPair();
        Log.d(TAG, "使用标准KeyStore成功生成密钥");
    }

    /**
     * 获取密钥的证书链
     */
    private static X509Certificate[] getAttestationCertificateChain() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        Certificate[] certificates = keyStore.getCertificateChain(KEY_ALIAS);
        if (certificates == null || certificates.length == 0) {
            return null;
        }

        X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
        for (int i = 0; i < certificates.length; i++) {
            x509Certificates[i] = (X509Certificate) certificates[i];
        }

        return x509Certificates;
    }

    /**
     * 从证书中提取Root of Trust信息
     */
    private static RootOfTrust extractRootOfTrust(X509Certificate cert) {
        try {
            byte[] extensionValue = cert.getExtensionValue(ATTESTATION_OID);
            if (extensionValue == null) {
                return null;
            }

            // 使用ASN.1解析
            ASN1Primitive asn1Primitive = getAsn1Primitive(extensionValue);
            if (!(asn1Primitive instanceof ASN1OctetString)) {
                return null;
            }

            byte[] extensionData = ((ASN1OctetString) asn1Primitive).getOctets();
            ASN1Primitive extensionObject = getAsn1Primitive(extensionData);
            if (!(extensionObject instanceof ASN1Sequence)) {
                return null;
            }

            return parseKeyAttestationSequence((ASN1Sequence) extensionObject);
        } catch (Exception e) {
            Log.e(TAG, "解析证书中的Root of Trust时出错", e);
            return null;
        }
    }

    private static ASN1Primitive getAsn1Primitive(byte[] data) throws IOException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(data))) {
            return asn1InputStream.readObject();
        }
    }

    private static RootOfTrust parseKeyAttestationSequence(ASN1Sequence attestationSequence) {
        try {
            // 处理不同格式的证书
            // 在不同设备上，证书格式可能有所不同

            // 尝试从TEE强制授权列表中查找
            if (attestationSequence.size() >= 8) {
                ASN1Encodable teeEnforced = attestationSequence.getObjectAt(7);
                if (teeEnforced instanceof ASN1Sequence) {
                    RootOfTrust rootOfTrust = findRootOfTrustInAuthList((ASN1Sequence) teeEnforced);
                    if (rootOfTrust != null) {
                        return rootOfTrust;
                    }
                }
            }

            // 尝试从软件强制授权列表查找
            if (attestationSequence.size() >= 7) {
                ASN1Encodable softwareEnforced = attestationSequence.getObjectAt(6);
                if (softwareEnforced instanceof ASN1Sequence) {
                    RootOfTrust rootOfTrust = findRootOfTrustInAuthList((ASN1Sequence) softwareEnforced);
                    if (rootOfTrust != null) {
                        return rootOfTrust;
                    }
                }
            }

            // 尝试直接在序列中查找
            for (int i = 0; i < attestationSequence.size(); i++) {
                if (attestationSequence.getObjectAt(i) instanceof ASN1Sequence) {
                    RootOfTrust rootOfTrust =
                            findRootOfTrustInAuthList((ASN1Sequence) attestationSequence.getObjectAt(i));
                    if (rootOfTrust != null) {
                        return rootOfTrust;
                    }
                }
            }

            return null;
        } catch (Exception e) {
            Log.e(TAG, "解析密钥认证序列时出错", e);
            return null;
        }
    }

    // 修复后的 findRootOfTrustInAuthList 方法
    private static RootOfTrust findRootOfTrustInAuthList(ASN1Sequence authList) {
        try {
            for (int i = 0; i < authList.size(); i++) {
                ASN1Encodable item = authList.getObjectAt(i);
                if (!(item instanceof ASN1TaggedObject)) continue; // 应该是 TaggedObject

                ASN1TaggedObject taggedItem = (ASN1TaggedObject) item;
                int tagNo = taggedItem.getTagNo();

                // 修正：RootOfTrust 的 Tag 是 704
                if (tagNo == 704) {
                    // RootOfTrust 是 SEQUENCE，通常是 EXPLICIT tagging
                    // 需要根据 BouncyCastle 版本适配，这里假设是 standard explicit
                    ASN1Encodable object = taggedItem.getObject();
                    if (object instanceof ASN1Sequence) {
                        return parseKeyAttestationSequenceRaw((ASN1Sequence) object);
                    }
                    // 有些版本可能是 OctetString 包装的 Sequence
                    if (object instanceof ASN1OctetString) {
                        try (ASN1InputStream is = new ASN1InputStream(((ASN1OctetString) object).getOctets())) {
                            ASN1Primitive seq = is.readObject();
                            if (seq instanceof ASN1Sequence) {
                                return parseKeyAttestationSequenceRaw((ASN1Sequence) seq);
                            }
                        }
                    }
                }
            }
            return null;
        } catch (Exception e) {
            Log.e(TAG, "解析授权列表出错", e);
            return null;
        }
    }

    // 对应上面调用的解析方法
    private static RootOfTrust parseKeyAttestationSequenceRaw(ASN1Sequence rootOfTrustSeq) {
        try {
            // RootOfTrust结构:
            // verifiedBootKey [0] OCTET_STRING
            // deviceLocked [1] BOOLEAN
            // verifiedBootState [2] ENUMERATED
            // verifiedBootHash [3] OCTET_STRING

            if (rootOfTrustSeq.size() < 3) return null;

            boolean deviceLocked = false;
            int verifiedBootState = 0;

            // BouncyCastle 解析 Sequence
            // 注意：ASN1Sequence 的顺序是固定的，不需要按 Tag 查找

            // Index 1: deviceLocked
            ASN1Encodable lockedObj = rootOfTrustSeq.getObjectAt(1);
            if (lockedObj instanceof ASN1Boolean) {
                deviceLocked = ((ASN1Boolean) lockedObj).isTrue();
            }

            // Index 2: verifiedBootState
            ASN1Encodable stateObj = rootOfTrustSeq.getObjectAt(2);
            if (stateObj instanceof ASN1Enumerated) { // 通常是 Enumerated
                verifiedBootState = ((ASN1Enumerated) stateObj).getValue().intValue();
            } else if (stateObj instanceof ASN1Integer) {
                verifiedBootState = ((ASN1Integer) stateObj).getValue().intValue();
            }

            return new RootOfTrust(deviceLocked, verifiedBootState);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 尝试直接从序列中解析RootOfTrust
     * 适用于一些非标准结构
     */
    private static RootOfTrust parseDirectSequence(ASN1Sequence sequence) {
        try {
            if (sequence.size() < 3) return null;

            // 尝试解析第二个元素为布尔值
            boolean deviceLocked = false;
            if (sequence.getObjectAt(1) instanceof ASN1Boolean) {
                deviceLocked = ((ASN1Boolean) sequence.getObjectAt(1)).isTrue();
            } else {
                return null; // 不符合格式
            }

            // 尝试解析第三个元素为整数
            int verifiedBootState = 0;
            if (sequence.getObjectAt(2) instanceof ASN1Integer) {
                verifiedBootState = ((ASN1Integer) sequence.getObjectAt(2)).getValue().intValue();
                return new RootOfTrust(deviceLocked, verifiedBootState);
            }

            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static RootOfTrust parseRootOfTrustValue(ASN1Encodable value) {
        try {
            if (!(value instanceof ASN1Sequence)) {
                return null;
            }

            ASN1Sequence rootOfTrustSeq = (ASN1Sequence) value;
            if (rootOfTrustSeq.size() < 3) {
                return null;
            }

            // 解析设备锁定状态
            boolean deviceLocked = false;
            if (rootOfTrustSeq.getObjectAt(1) instanceof ASN1Boolean) {
                deviceLocked = ((ASN1Boolean) rootOfTrustSeq.getObjectAt(1)).isTrue();
            }

            // 解析验证引导状态
            int verifiedBootState = 0;
            if (rootOfTrustSeq.getObjectAt(2) instanceof ASN1Integer) {
                verifiedBootState = ((ASN1Integer) rootOfTrustSeq.getObjectAt(2)).getValue().intValue();
            }

            return new RootOfTrust(deviceLocked, verifiedBootState);
        } catch (Exception e) {
            Log.e(TAG, "解析Root of Trust值时出错", e);
            return null;
        }
    }

    /**
     * Root of Trust信息类
     */
    private static class RootOfTrust {
        private final boolean deviceLocked;
        private final int verifiedBootState;

        RootOfTrust(boolean deviceLocked, int verifiedBootState) {
            this.deviceLocked = deviceLocked;
            this.verifiedBootState = verifiedBootState;
        }

        boolean isDeviceLocked() {
            return deviceLocked;
        }

        int getVerifiedBootState() {
            return verifiedBootState;
        }
    }
}