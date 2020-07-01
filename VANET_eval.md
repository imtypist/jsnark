# VANET evaluation

## setting

- 使用`jsnark`来构建zkSNARKs，根据`libsnark`提供的3种零知识证明算法的经验性能比较，最终选定较优的[Groth16](https://github.com/akosba/libsnark/tree/master/libsnark/zk_proof_systems/ppzksnark)技术方案
- 实验环境使用`ubuntu14.04`，运行在VirtualBox上，虚拟机分配CPU数量为2，分配内存为4GB，主机的CPU配置为`Intel i7-7700`，内存为16GB

## performance

- [rsa2048_encryption.log](./rsa2048_encryption.log)
- [rsa2048_sha256_sig_verify.log](./rsa2048_sha256_sig_verify.log)

