#include <bits/stdc++.h>
using namespace std;
typedef long long int ll;
typedef unsigned long long int ull;

ll dp[1111111];
ll prv[1111111];
ll whi[1111111];
ll nxt[1111111][2];
ll cst[1111111][2];
int indeg[1111111];
int outdeg[1111111];
priority_queue< pair<ll, ll> > PQ;


void gogo(int x) {
    vector<int> path; path.clear();
    while(x != 0) {
        path.push_back(whi[x]);
        x = prv[x];
    }
    string s = "";
    reverse(path.begin(), path.end());
    cout << path.size() << endl;
    for(int i=0 ; i<path.size() ; i+=8) {
        int v = 0;
        for(int j=0 ; i+j < path.size() && j<8 ; j++) {
            v += (int(path[i + j]) << j);
        }
        s += (char)(v);
        cout << v << " ";
    }
    cout << s << endl;
}

int main(void)
{
    int i, a, b, c, d;
    freopen("output.txt", "r", stdin);
    for(int i=1 ; i<=50942 ; i++) {
        cin >> a >> b >> c >> d;
        nxt[a][c] = b;
        cst[a][c] = d;
        indeg[b]++;
        outdeg[a]++;
    }
    for(int i=1 ; i<1000000 ; i++) dp[i] = 1 << 30;
    dp[0] = 0; PQ.push(make_pair(0, 0));
    while(!PQ.empty())
    {
        pair<ll, ll> X = PQ.top(); PQ.pop();
        ll cdist = -X.first; ll cloc = X.second;
        if(indeg[cloc] == 0) continue;
        if(dp[cloc] != cdist) continue;
        for(int i=0 ; i<2 ; i++) {
            int nxtv = nxt[cloc][i];
            int nxtdist = cst[cloc][i] + cdist;
            if(dp[nxtv] > nxtdist) {
                dp[nxtv] = nxtdist;
                whi[nxtv] = i;
                prv[nxtv] = cloc;
                PQ.push(make_pair(-dp[nxtv], nxtv));
            }
        }
    }
    for(int i=0 ; i<1000000 ; i++) {
        if(dp[i] == 18906 && outdeg[i] == 0) {
            cout << i << endl;
            gogo(i);
        }
    }
}