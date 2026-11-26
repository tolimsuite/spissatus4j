package cn.tolim.spissatus4j.contract.key;

/**
 * Factory that lets the key module contribute an appropriately configured
 * manager without making the core module depend on any concrete provider.
 */
public interface KeyManagerFactory {

    String factoryId();

    KeyManager create(KeyManagerDependencies dependencies);
}