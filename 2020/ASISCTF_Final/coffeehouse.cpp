#include <bits/stdc++.h>
#define fio ios::sync_with_stdio(false);cin.tie(0);cout.tie(0);
using namespace std;
typedef long long int ll;
typedef unsigned long long int ull;
typedef long double ldb;
mt19937 rng(chrono::steady_clock::now().time_since_epoch().count());
const int mod=2;

int d = 0xf00d;
int enc[18] = {12263, 64385, 17263, 21844, 59059, 40727, 12495, 21699, 58982, 30941, 52310, 2067, 52933, 47229, 28811, 45010, 3549, 61620};
int rk[4];
const int M=(1 << 16);

int top_bit(int x) { return (x >> 8); }
int bot_bit(int x) { return x & 255; }

pair<int, int> decrypt(int u, int v)
{
	int s = (32 * d) % M; int x, w;
	for(int i=0 ; i<32 ; i++)
	{
		x = (((u << 4) + rk[2]) ^ (u + s) ^ ((u >> 5) + rk[3])) % M;
		v = (v + M - x) % M;
		w = (((v << 4) + rk[0]) ^ (v + s) ^ ((v >> 5) + rk[1])) % M;
		u = (u + M - w) % M;
		s = (s + M - d) % M;
	}
	return make_pair(u, v);
}

bool isok(int x) { return 32 <= x && x < 127; }

void work_decryption(void)
{
	string s; pair<int, int> CC; 
	int aa, bb, cc, dd; char aaa, bbb, ccc, ddd;
	for(int i=0 ; i<18 ; i+=2)
	{
		CC = decrypt(enc[i], enc[i+1]);
		aa = top_bit(CC.first); 
		bb = bot_bit(CC.first);
		cc = top_bit(CC.second);
		dd = bot_bit(CC.second);
		if(!isok(aa) || !isok(bb) || !isok(cc) || !isok(dd)) return;
		aaa = aa; bbb = bb; ccc = cc; ddd = dd;
		s.push_back(aaa); s.push_back(bbb); s.push_back(ccc); s.push_back(ddd);
		if(i==0 && s != "++ A") return;
		if(i==1 && s != "++ ASIS{") return;
	}
	cout<<s<<endl;
}


int main(void)
{
	for(int key_1 = 0 ; key_1 < (1 <<16) ; key_1++)
	{
		if(key_1 % 1000 == 0) cout<<key_1/1000<<endl;
		for(int key_2 = 0 ; key_2 < (1<<16) ; key_2++)
		{
			rk[0]=key_1;
			rk[1]=key_2;
			rk[2]=key_1^key_2;
			rk[3]=(key_1&key_2);
			work_decryption();
		}
	}
	return 0;
}