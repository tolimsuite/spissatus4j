package cn.tolim.spissatus4j.core.builder;

import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.ExtensionRegistry;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Mutable collection bucket filled by module contributions and explicit builder calls. */
final class ModuleContributions {

    final Map<String, AlgorithmProvider> algorithmProviders = new LinkedHashMap<>();
    final Map<String, KeyProvider> keyProviders = new LinkedHashMap<>();
    final Map<String, KeyManagerFactory> keyManagerFactories = new LinkedHashMap<>();
    final List<EnvelopeCodec> envelopeCodecs = new ArrayList<>();
    EnvelopeService envelopeService;
    StreamCipherService streamCipherService;
    RandomService randomService;
    PolicyEngine policyEngine;
    final List<PolicyProvider> policyProviders = new ArrayList<>();
    final List<AuditSink> auditSinks = new ArrayList<>();
    MetricsRecorder metricsRecorder;
    final List<AlertSink> alertSinks = new ArrayList<>();
    final List<KeyWrapper> keyWrappers = new ArrayList<>();
    final Map<String, String> settings = new LinkedHashMap<>();
    final Map<String, String> attributes = new LinkedHashMap<>();
    final List<SpissatusModule> modules = new ArrayList<>();
    final List<String> rejectedModules = new ArrayList<>();
    ExtensionRegistry extensionRegistry;
}