
#include <iostream>
#include "graph_search.h"


/* -------------------------------------------------------
   Directed / Undirected helpers
------------------------------------------------------- */

template <typename Node, typename Cost>
void addDirectedEdge(iar::utils::AdjacencyList<Node, Cost>& g, Node a, Node b, Cost w)
{
    g[a].push_back({b, w});
}

template <typename Node, typename Cost>
void addUndirectedEdge(iar::utils::AdjacencyList<Node, Cost>& g, Node a, Node b, Cost w)
{
    g[a].push_back({b, w});
    g[b].push_back({a, w});
}

/* -------------------------------------------------------
   Tests
------------------------------------------------------- */

bool test_dijkstra_basic()
{
    iar::utils::AdjacencyList<int, int> g;
    addDirectedEdge(g, 1, 2, 1);
    addDirectedEdge(g, 2, 3, 2);
    addDirectedEdge(g, 1, 3, 10);

    iar::utils::Dijkstra<int, int> d(g);
    auto path = d.computePath(1, 3);

    return path == std::vector<int>{1, 2, 3};
}

bool test_astar_basic()
{
    iar::utils::AdjacencyList<int, int> g;
    addDirectedEdge(g, 1, 2, 1);
    addDirectedEdge(g, 2, 3, 2);
    addDirectedEdge(g, 1, 3, 10);

    auto heuristic = [](int a, int b) { return 0; };

    iar::utils::AStar<int, int> a(g, heuristic);
    auto path = a.computePath(1, 3);

    return path == std::vector<int>{1, 2, 3};
}

bool test_bellman_ford_negative_cycle()
{
    iar::utils::AdjacencyList<int, int> g;
    addDirectedEdge(g, 1, 2, 1);
    addDirectedEdge(g, 2, 3, -2);
    addDirectedEdge(g, 3, 1, -1);

    iar::utils::BellmanFord<int, int> bf(g);
    return bf.hasNegativeCycle(1);
}
