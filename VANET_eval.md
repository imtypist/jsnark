# VANET evaluation

## setting

- 使用`jsnark`来构建zkSNARKs，根据`libsnark`提供的3种零知识证明算法的经验性能比较，最终选定较优的[Groth16](https://github.com/akosba/libsnark/tree/master/libsnark/zk_proof_systems/ppzksnark)技术方案
- 实验环境使用`ubuntu14.04`，运行在VirtualBox上，虚拟机分配CPU数量为2，分配内存为4GB，主机的CPU配置为`Intel i7-7700`，内存为16GB

## performance

The RSA key length is set to 2048 bits, which is safe enough currently.

- [rsa2048_encryption.log](./rsa2048_encryption.log)
- [rsa2048_sha256_sig_verify.log](./rsa2048_sha256_sig_verify.log)
- [vanet_rsa2048.log](./vanet_rsa2048.log)

The output below is the testcase for VANET, the example input is a pseudo random address concatenating a piece of GPS raw data.

```bash
Running Circuit Generator for < vanet_rsa2048 >
Circuit Generation Done for < vanet_rsa2048 >  
 	 Total Number of Constraints :  414319

PlainText:0xd91c747b4a76B8013Aa336Cbc52FD95a7a9BD3D9$GPRMC,092927.000,A,2235.9058,N,11400.0518,E,0.000,74.11,151216,,D*49
Running Circuit Evaluator for < vanet_rsa2048 >
	[output] Value of Wire # 1277072 (Is Signature valid?) :: 1
	[output] Value of Wire # 2226921 (Output cipher text[0]) :: 1251022490261258172529308360859369551837157967434844421554503068336263232
	[output] Value of Wire # 2226922 (Output cipher text[1]) :: 782513615157148428896018740256285560893017553685924761331573477021861754
	[output] Value of Wire # 2226923 (Output cipher text[2]) :: 297893711879754138931627910652983846133902364790173190431445656834653104
	[output] Value of Wire # 2226924 (Output cipher text[3]) :: 1062246178463496446723238490343351688931627517611251013590768981856952089
	[output] Value of Wire # 2226925 (Output cipher text[4]) :: 283619758270485012554111906691482726594266063316848294719061553920244069
	[output] Value of Wire # 2226926 (Output cipher text[5]) :: 1605604628605955420311218435655442487833758868828180874969980792959738819
	[output] Value of Wire # 2226927 (Output cipher text[6]) :: 1765324337636077192622074629173695556494918446370154704523581054010828502
	[output] Value of Wire # 2226928 (Output cipher text[7]) :: 229242121535333726124694280674701732758091959395234671423966224579886508
	[output] Value of Wire # 2226929 (Output cipher text[8]) :: 41995595892867847343690929056587572862
Circuit Evaluation Done for < vanet_rsa2048 >

```
