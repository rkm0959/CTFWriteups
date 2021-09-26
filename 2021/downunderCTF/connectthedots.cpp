#include <bits/stdc++.h>
using namespace std;
typedef long long int ll;
typedef unsigned long long int ull;

string ans;
int data[14400];
vector< pair<string, int> > edge[3600];
int fin[8];
int ORD[8] = {6, 3, 7, 5, 1, 4, 0, 2};

int dist[3600];
int prv[3600];
string pv[3600];
queue<int> Q;

void gogo(int st, int en) {
    for(int i=0 ; i<3600 ; i++) dist[i] = 1e9;
    for(int i=0 ; i<3600 ; i++) prv[i] = -1;
    for(int i=0 ; i<3600 ; i++) pv[i] = "";
    dist[st] = 0; prv[st] = st; Q.push(st);
    while(!Q.empty()) {
        int x = Q.front(); Q.pop();
        for(int i=0 ; i<edge[x].size() ; i++) {
            int nx = edge[x][i].second;
            if(dist[nx] > dist[x] + 1) {
                dist[nx] = dist[x] + 1;
                prv[nx] = x;
                pv[nx] = edge[x][i].first;
                Q.push(nx);
            }
        }
    }
    string cc = "";
    int cur = en;
    while(cur != st) {
        cc += pv[cur];
        cur = prv[cur];
    }
    reverse(cc.begin(), cc.end());
    ans += cc + "x";
}

int main(void)
{
    ios::sync_with_stdio(false); cin.tie(0); cout.tie(0);
    freopen("data.txt", "r", stdin);
    for(int i=0 ; i<14400 ; i++) cin >> data[i];
    for(int i=0 ; i<3600 ; i++) 
    {
        int val = data[4 * i];
        if((val & 1) == 0 && i-1 >= 0) {
            edge[i].push_back(make_pair("h", i-1));
        }
        if((val & 2) == 0 && i+60 < 3600) {
            edge[i].push_back(make_pair("j", i+60));
        }
        if((val & 4) == 0 && i+1 < 3600) {
            edge[i].push_back(make_pair("l", i+1));
        }
        if((val & 8) == 0 && i-60 >= 0) {
            edge[i].push_back(make_pair("k", i-60));
        }
        if((val & 128) == 128) {
            fin[(val >> 4) & 7] = i;
        }
    }
    for(int i=-1 ; i<=6 ; i++) {
        if(i == -1) gogo(0, fin[ORD[i+1]]);
        else gogo(fin[ORD[i]], fin[ORD[i+1]]);
    }
    cout << ans << endl;
    cout << ans.length() << endl;
}