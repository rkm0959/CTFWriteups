#include <bits/stdc++.h>
#include <omp.h>
using namespace std;
typedef long long int ll;
typedef unsigned long long int ull;

bool bits2[160000];
bool bits3[160000];
bool bits[160000];
int vals[65536];

ull key2;
ll TOT;

void LETSGO(ull vv)
{
    bool lfsr[350] = {0};
    bool nfsr[350] = {0};
    for(int i=0 ; i<48 ; i++)
        nfsr[i] = (vv >> (63 - i)) & 1;
    for(int i=0 ; i<16 ; i++)
        lfsr[i] = (vv >> (15 - i)) & 1;
    
    int res = 0;
    for(int i=0 ; i<300 ; i++)
    {
        int h = (lfsr[i + 4] ^ lfsr[i + 15]);
        h ^= (lfsr[i + 2] & lfsr[i + 15]);
        h ^= (lfsr[i + 2] & lfsr[i + 4] & lfsr[i + 7]);
        h ^= (lfsr[i + 2] & lfsr[i + 7] & lfsr[i + 15]);
        h ^= (lfsr[i + 2] & lfsr[i + 7] & nfsr[i + 27]);
        h ^= (lfsr[i + 2] & lfsr[i + 4] & lfsr[i + 7] & nfsr[i + 27]);
        int f = nfsr[i] ^ h;
        int g = lfsr[i] ^ nfsr[i + 2];
        g ^= nfsr[i + 5];
        g ^= nfsr[i + 9];
        g ^= nfsr[i + 15];
        g ^= nfsr[i + 22];
        g ^= nfsr[i + 26];
        g ^= nfsr[i + 39];
        g ^= (nfsr[i + 26] & nfsr[i + 30]);
        g ^= (nfsr[i + 5] & nfsr[i + 9]);
        g ^= (nfsr[i + 15] & nfsr[i + 22] & nfsr[i + 26]);
        g ^= (nfsr[i + 15] & nfsr[i + 22] & nfsr[i + 39]);
        g ^= (nfsr[i + 9] & nfsr[i + 22] & nfsr[i + 26] & nfsr[i + 39]);
        nfsr[i + 48] = g;
        lfsr[i + 16] = (lfsr[i] ^ lfsr[i + 1] ^ lfsr[i + 12] ^ lfsr[i + 15]);
        if(bits2[i] != bits3[i] && f != bits[i]) return;
    }
    cout << vv << "\n";
    exit(0);   
}

void works(int v)
{
    int K3 = v;
    int res[48] = {0};
    int lfsr[64] = {0};
    int CALL[48] = {0};
    int act[64] = {0};
    int V[16] = {0};
    int W[16] = {0};

    for(int i=0 ; i<16 ; i++) lfsr[i] = (v >> (15 - i)) & 1;
    for(int i=0 ; i<48 ; i++) lfsr[i + 16] = lfsr[i] ^ lfsr[i + 1] ^ lfsr[i + 12] ^ lfsr[i + 15];
    for(int i=0 ; i<48 ; i++) 
    {
        res[i] = (lfsr[i + 4] ^ lfsr[i + 15]);
        res[i] ^= (lfsr[i + 2] & lfsr[i + 15]);
        res[i] ^= (lfsr[i + 2] & lfsr[i + 4] & lfsr[i + 7]);
        res[i] ^= (lfsr[i + 2] & lfsr[i + 7] & lfsr[i + 15]);
    }
    for(int i=0 ; i<48 ; i++) CALL[i] = -1;
    for(int i=0 ; i<48 ; i++)
        if(bits2[i] != bits3[i]) CALL[i] = bits[i] ^ res[i];
    for(int i=0 ; i<16 ; i++) act[48 + i] = lfsr[i];
    for(int i=0 ; i<48 ; i++) act[i] = CALL[i];

    int cnt = 0;
    for(int i=0 ; i<16 ; i++)
        if(CALL[i + 32] == -1) V[cnt++] = i + 32;
    
    for(int i=0 ; i<(1<<cnt) ; i++)
    {
        bool ok = true;
        for(int j=0 ; j<cnt ; j++)
            act[V[j]] = (i >> j) & 1;
        
        int xored = 0;
        for(int j=0 ; j<16 ; j++)
            xored ^= ((act[32 + j] ^ act[48 + j]) << (15 - j));
        
        for(int j=0 ; j<32 ; j++) act[j] = CALL[j];

        int VAL = vals[xored];
        int bts[16] = {0};
        for(int j=0 ; j<16 ; j++) bts[j] = (VAL >> (15 - j)) & 1;
        int cntt = 0;
        for(int j=0 ; j<16 ; j++)
        {
            if(act[j] == -1 && act[j + 16] == -1) W[cntt++] = j;
            else if(act[j] == -1) act[j] = bts[j] ^ act[j + 16];
            else if(act[j + 16] == -1) act[j + 16] = bts[j] ^ act[j];
            else
            {
                if(act[j] ^ act[j+16] != bts[j]) 
                {
                    ok = false;
                    break;
                }
            }
        }
        if(!ok) continue;
        for(int j=0 ; j<(1<<cntt) ; j++) 
        {
            for(int k=0 ; k<cntt ; k++)
            {
                if(((j >> k) & 1) == 1)
                {
                    act[W[k]] = 1;
                    act[W[k] + 16] = bts[W[k]] ^ act[W[k]];
                }
                else 
                {
                    act[W[k]] = 0;
                    act[W[k] + 16] = bts[W[k]] ^ act[W[k]];
                } 
            }
            ull val = 0;
            for(int i=0 ; i<64 ; i++) val = 2 * val + int(act[i]);
            LETSGO(val); TOT += 1;
            // if(TOT % 10000000 == 0) cerr << TOT / 10000000 << "\n";
        }
    }
}

int main(void)
{
    ios::sync_with_stdio(false); 
    double T = clock();
    freopen("input.txt", "r", stdin);
    freopen("output.txt", "w", stdout);
    for(int i=0 ; i<160000 ; i++) cin >> bits2[i];
    for(int i=0 ; i<160000 ; i++) cin >> bits3[i];
    for(int i=0 ; i<160000 ; i++) cin >> bits[i];
    for(int i=0 ; i<65536 ; i++) cin >> vals[i];
    cin >> key2;
    omp_set_num_threads(10);
    #pragma omp parallel for schedule(dynamic)
    for(int i=1 ; i<65536 ; i++) {
        works(i);
    }
   
    cerr << TOT << "\n";
    cerr << (clock() - T) / CLOCKS_PER_SEC << "\n";
    return 0;
}

