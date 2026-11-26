package cn.tolim.spissatus4j.starter;

import static org.assertj.core.api.Assertions.assertThat;

import cn.tolim.spissatus4j.starter.cli.SpissatusCli;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SpissatusCliTest {

    private static PrintStream nullStream() {
        return new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
    }

    private static int run(String[] args, ByteArrayOutputStream out, ByteArrayOutputStream err) {
        return SpissatusCli.run(args, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    @Test
    void helpAndDemoWork() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        assertThat(run(new String[]{"--help"}, out, err)).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("spissatus4j CLI");

        out.reset();
        err.reset();
        assertThat(run(new String[]{"demo"}, out, err)).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("DEMO OK");
    }

    @Test
    void selfCheckAndCapabilitiesWork() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        assertThat(run(new String[]{"self-check"}, out, err)).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("state=READY");
        out.reset();
        assertThat(run(new String[]{"capabilities"}, out, err)).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("provider jca");
    }

    @Test
    void persistentKeySignVerifyFlow(@TempDir Path directory) throws Exception {
        Path message = directory.resolve("message.txt");
        Files.writeString(message, "cli signature message");
        Path signature = directory.resolve("message.sig");
        String[] store = {"--store-dir", directory.toString(), "--master-password", "cli-password"};

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        String[] generate = concat(new String[]{"generate-key", "--id", "cli-sign",
                "--algorithm", "ED25519", "--type", "ED25519", "--tenant", "system"}, store);
        assertThat(run(generate, out, err)).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("keyId=cli-sign");

        out.reset();
        String[] generateAes = concat(new String[]{"generate-key", "--id", "cli-aes",
                "--algorithm", "AES-GCM", "--type", "AES", "--tenant", "system"}, store);
        assertThat(run(generateAes, out, err)).isZero();

        Path envelope = directory.resolve("message.envelope");
        Path decrypted = directory.resolve("message.decrypted");
        out.reset();
        String[] encrypt = concat(new String[]{"encrypt", "--key", "cli-aes",
                "--in", message.toString(), "--out", envelope.toString(),
                "--tenant", "system"}, store);
        assertThat(run(encrypt, out, err)).isZero();
        assertThat(Files.exists(envelope)).isTrue();
        assertThat(out.toString(StandardCharsets.UTF_8))
                .contains("algorithm=AES-GCM", "envelopeVersion=2");

        out.reset();
        String[] decrypt = concat(new String[]{"decrypt", "--in", envelope.toString(), "--out",
                decrypted.toString(), "--tenant", "system"}, store);
        assertThat(run(decrypt, out, err)).isZero();
        assertThat(Files.readString(decrypted)).isEqualTo("cli signature message");

        out.reset();
        String[] inspect = concat(new String[]{"inspect-envelope", "--in", envelope.toString()},
                store);
        assertThat(run(inspect, out, err)).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8))
                .contains("algorithm=AES-GCM", "headerHash=present", "version=2");

        out.reset();
        String[] sign = concat(new String[]{"sign", "--key", "cli-sign", "--algorithm",
                "ED25519", "--in", message.toString(), "--out", signature.toString(),
                "--tenant", "system"}, store);
        assertThat(run(sign, out, err)).isZero();
        assertThat(Files.exists(signature)).isTrue();

        out.reset();
        String[] verify = concat(new String[]{"verify", "--key", "cli-sign", "--algorithm",
                "ED25519", "--in", message.toString(), "--signature", signature.toString(),
                "--tenant", "system"}, store);
        assertThat(run(verify, out, err)).isZero();
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("signature valid");
    }

    private static String[] concat(String[] first, String[] second) {
        String[] result = new String[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}