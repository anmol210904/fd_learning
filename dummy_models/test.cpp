#include <bits/stdc++.h>
using namespace std;

int main() {
    int num;
    cin >> num;

    vector<tuple<int, int, int>> arr;
    arr.reserve(num);  // ✅ Reserve space

    for (int i = 0; i < num; i++) {
        int a, b, c;
        cin >> a >> b >> c;
        arr.push_back({a, b, c});
    }

    sort(arr.begin(), arr.end());  // ✅ Sorts lexicographically (a,b,c)

    queue<pair<int, int>> normal;
    queue<pair<int, int>> vip;

    // ✅ Separate VIP and Normal
    for (int i = 0; i < num; i++) {
        if (get<2>(arr[i]) == 1) {  // ✅ Correct tuple access
            vip.push({get<0>(arr[i]), get<1>(arr[i])});
        } else {
            normal.push({get<0>(arr[i]), get<1>(arr[i])});
        }
    }

    // ✅ Print VIP queue
    cout << "VIP Queue:\n";
    queue<pair<int, int>> temp1 = vip; // Copy for printing (to not destroy original)
    while (!temp1.empty()) {
        cout << "(" << temp1.front().first << ", " << temp1.front().second << ")\n";
        temp1.pop();
    }

    // ✅ Print Normal queue
    cout << "\nNormal Queue:\n";
    queue<pair<int, int>> temp2 = normal;
    while (!temp2.empty()) {
        cout << "(" << temp2.front().first << ", " << temp2.front().second << ")\n";
        temp2.pop();
    }

    return 0;
}