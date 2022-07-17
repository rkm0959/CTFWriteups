#include <bitset>
#include <iostream>
#include <random>
#include <algorithm>
using namespace std;
typedef long long int ll;

const int N = 56;
const int SZ = 32508;
const int USE = 45000;
string s;

bitset<SZ + 1> bs[USE];
bitset<N> cur_stack[65537];
int sol[SZ];
int dg[20] = {33, 30, 26, 25, 24, 23, 22, 21, 20, 18, 13, 12, 11, 10, 7, 5, 4, 2, 1, 0};
int S1[N];
int S2[N][N];
int S3[N][N][N];
int a[3];

int S1c(int x) {
    return S1[x];
}

int S2c(int x, int y) {
    if(x < y) return S2[x][y];
    return S2[y][x];
}

int S3c(int x, int y, int z) {
    a[0] = x; a[1] = y; a[2] = z;
    sort(a, a + 3);
    return S3[a[0]][a[1]][a[2]];
}


void update_single(int eq, int whi) {
    for(int i = 0 ; i < N ; i++) {
        if(cur_stack[whi].test(i)) bs[eq].flip(S1[i]);
    }
}

void update_double(int eq, int whi1, int whi2) {
    for(int i = 0 ; i < N ; i++) {
        if(!cur_stack[whi1].test(i)) continue;
        for(int j = 0 ; j < N ; j++) {
            if(!cur_stack[whi2].test(j)) continue;
            bs[eq].flip(S2c(i, j));
        }
    }
}

void update_triple(int eq, int whi1, int whi2, int whi3) {
     for(int i = 0 ; i < N ; i++) {
        if(!cur_stack[whi1].test(i)) continue;
        for(int j = 0 ; j < N ; j++) {
            if(!cur_stack[whi2].test(j)) continue;
            for(int k = 0 ; k < N ; k++) {
                if(!cur_stack[whi3].test(k)) continue;
                bs[eq].flip(S3c(i, j, k));
            }
        }
    }
}



int main(void) {
    freopen("input.txt", "r", stdin);
    ios::sync_with_stdio(false); cin.tie(0);  srand(time(NULL));
    cin >> s; assert(s.length() == 65472);

    int cc = 0;
    for(int i = 0 ; i < N ; i++) S1[i] = cc++;
    for(int i = 0 ; i < N ; i++)
        for(int j = i ; j < N ; j++) S2[i][j] = cc++;
    for(int i = 0 ; i < N ; i++)
        for(int j = i ; j < N ; j++)
            for(int k = j ; k < N ; k++) S3[i][j][k] = cc++;
    
    assert(cc == SZ);

    ll t = clock();
    
    for(int i = 0 ; i < 64 ; i++) {
        cur_stack[i].reset();
        if(i % 8 == 0) continue;
        cur_stack[i].set(i - i / 8 - 1);
    }
    
    for(int i = 64 ; i < 65536 ; i++) {
        if(i % 1000 == 0) cout << i << endl;
        cur_stack[i].reset();
        for(int j = 0 ; j < 20 ; j++) {
            cur_stack[i] ^= cur_stack[i - 64 + dg[j]];
        }
    }

    cout << "cur_stack finished" << endl;
    cout << (clock() - t) / CLOCKS_PER_SEC << endl;


    for(int i = 0 ; i < USE ; i++) {
        if(i % 1000 == 0) cout << i << endl;
        update_single(i, i);
        update_single(i, i + 12);
        update_single(i, i + 18);
        update_single(i, i + 36);
        update_single(i, i + 62);
        update_double(i, i + 2, i + 8);
        update_double(i, i + 20, i + 34);
        update_double(i, i + 27, i + 60);
        update_double(i, i + 31, i + 34);
        update_double(i, i + 48, i + 63);
        update_double(i, i + 15, i + 50);
        update_double(i, i + 25, i + 49);
        update_double(i, i + 7, i + 49);
        update_triple(i, i + 10, i + 13, i + 61);
        update_triple(i, i + 29, i + 32, i + 37);
        update_triple(i, i + 6, i + 9, i + 42);
        update_triple(i, i + 26, i + 55, i + 59);
        update_triple(i, i + 29, i + 41, i + 42);
        update_triple(i, i + 24, i + 28, i + 58);
        if(s[i] == '1') bs[i].set(SZ);
    }

    cout << "matrix building done" << endl;
    cout << (clock() - t) / CLOCKS_PER_SEC << endl;

    for(int i = 0 ; i < SZ ; i++) {
        if(i % 1000 == 0) cout << i << endl;
        for(int j = i ; j < USE ; j++) {
            if(bs[j].test(i)) {
                if(j != i) swap(bs[i], bs[j]);
                break;
            }
        }
        assert(bs[i].test(i));
        for(int j = i + 1 ; j < USE ; j++) {
            if(bs[j].test(i)) bs[j] ^= bs[i];
        }
    }
    for(int i = SZ - 1 ; i >= 0 ; i--) {
        if(i % 1000 == 0) cout << i << endl;
        assert(bs[i].test(i));
        sol[i] = 0;
        if(bs[i].test(SZ)) sol[i] = 1;
        for(int j = i + 1 ; j < SZ ; j++) {
            if(bs[i].test(j) && sol[j] == 1) sol[i] ^= 1;
        }
    }
    for(int i = 0 ; i < 56 ; i++) {
        cout << sol[i];
    }
    return 0;
}