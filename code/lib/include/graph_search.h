#pragma once

#include <unordered_map>
#include <vector>
#include <queue>
#include <limits>
#include <functional>
#include <stdexcept>
#include <algorithm>

namespace iar { namespace utils {

/* =========================
   Graph / Edge Definitions
   ========================= */

template <typename Node, typename Cost>
using Edge = std::pair<Node, Cost>;

template <typename Node, typename Cost,
          typename Hash = std::hash<Node>,
          typename Equal = std::equal_to<Node>>
using AdjacencyList =
    std::unordered_map<Node, std::vector<Edge<Node, Cost>>, Hash, Equal>;


/* =========================
   Common Interface
   ========================= */

template <typename Node, typename Cost>
class ISearch
{
public:
    virtual ~ISearch() = default;

    virtual std::vector<Node> computePath(const Node& start, const Node& goal) = 0;

    virtual const std::unordered_map<Node, Cost>& gScores() const = 0;
};


/* =========================
   Base class (shared core)
   ========================= */

template <typename Node, typename Cost,
          typename Hash = std::hash<Node>,
          typename Equal = std::equal_to<Node>>
class SearchBase : public ISearch<Node, Cost>
{
public:
    using Graph = AdjacencyList<Node, Cost, Hash, Equal>;

    explicit SearchBase(const Graph& graph)
        : graph_(graph)
    {
    }

    const std::unordered_map<Node, Cost, Hash, Equal>& gScores() const override
    {
        return gScore_;
    }

protected:
    const Graph& graph_;
    std::unordered_map<Node, Node, Hash, Equal> cameFrom_;
    std::unordered_map<Node, Cost, Hash, Equal> gScore_;

    void initialize(const Node& start)
    {
        cameFrom_.clear();
        gScore_.clear();
        gScore_[start] = Cost{};
    }

    std::vector<Node> reconstructPath(const Node& start, const Node& goal)
    {
        std::vector<Node> path;
        Node current = goal;

        while (current != start)
        {
            path.push_back(current);
            current = cameFrom_.at(current);
        }

        path.push_back(start);
        std::reverse(path.begin(), path.end());
        return path;
    }
};


/* =========================
   Dijkstra Implementation
   ========================= */

template <typename Node, typename Cost,
          typename Hash = std::hash<Node>,
          typename Equal = std::equal_to<Node>>
class Dijkstra : public SearchBase<Node, Cost, Hash, Equal>
{
public:
    using typename SearchBase<Node, Cost, Hash, Equal>::Graph;

    explicit Dijkstra(const Graph& graph)
        : SearchBase<Node, Cost, Hash, Equal>(graph)
    {
    }

    std::vector<Node> computePath(const Node& start, const Node& goal) override;
};


/* =========================
   A* Implementation
   ========================= */

template <typename Node, typename Cost,
          typename Hash = std::hash<Node>,
          typename Equal = std::equal_to<Node>>
class AStar : public SearchBase<Node, Cost, Hash, Equal>
{
public:
    using typename SearchBase<Node, Cost, Hash, Equal>::Graph;
    using HeuristicFn = std::function<Cost(const Node&, const Node&)>;

    AStar(const Graph& graph, HeuristicFn heuristic)
        : SearchBase<Node, Cost, Hash, Equal>(graph),
          heuristic_(heuristic)
    {
    }

    std::vector<Node> computePath(const Node& start, const Node& goal) override;

private:
    HeuristicFn heuristic_;
};


/* =========================
   Bellman-Ford (negative weights)
   ========================= */

template <typename Node, typename Cost,
          typename Hash = std::hash<Node>,
          typename Equal = std::equal_to<Node>>
class BellmanFord
{
public:
    using Graph = AdjacencyList<Node, Cost, Hash, Equal>;
    using EdgeList = std::vector<std::tuple<Node, Node, Cost>>;

    explicit BellmanFord(const Graph& graph)
        : graph_(graph)
    {
        buildEdgeList();
    }

    std::unordered_map<Node, Cost, Hash, Equal> computeDistances(const Node& start);
    bool hasNegativeCycle(const Node& start);

private:
    void buildEdgeList();

    const Graph& graph_;
    EdgeList edges_;
};

} } // namespace iar::utils



namespace iar { namespace utils {

/* ---------------------------
   Dijkstra
--------------------------- */

template <typename Node, typename Cost, typename Hash, typename Equal>
std::vector<Node> Dijkstra<Node, Cost, Hash, Equal>::computePath(
    const Node& start, const Node& goal)
{
    this->initialize(start);

    using QueueElement = std::pair<Cost, Node>;
    std::priority_queue<QueueElement,
                        std::vector<QueueElement>,
                        std::greater<QueueElement>> openSet;

    openSet.emplace(Cost{}, start);

    while (!openSet.empty())
    {
        Node current = openSet.top().second;
        openSet.pop();

        if (current == goal)
            return this->reconstructPath(start, goal);

        auto it = this->graph_.find(current);
        if (it == this->graph_.end())
            continue;

        for (const auto& [neighbor, edgeCost] : it->second)
        {
            Cost tentativeG = this->gScore_[current] + edgeCost;

            auto gs = this->gScore_.find(neighbor);
            if (gs == this->gScore_.end() || tentativeG < gs->second)
            {
                this->cameFrom_[neighbor] = current;
                this->gScore_[neighbor] = tentativeG;
                openSet.emplace(tentativeG, neighbor);
            }
        }
    }

    throw std::runtime_error("Goal node is unreachable");
}


/* ---------------------------
   A*
--------------------------- */

template <typename Node, typename Cost, typename Hash, typename Equal>
std::vector<Node> AStar<Node, Cost, Hash, Equal>::computePath(
    const Node& start, const Node& goal)
{
    this->initialize(start);

    using QueueElement = std::pair<Cost, Node>;
    std::priority_queue<QueueElement,
                        std::vector<QueueElement>,
                        std::greater<QueueElement>> openSet;

    std::unordered_map<Node, bool, Hash, Equal> closedSet;

    openSet.emplace(heuristic_(start, goal), start);

    while (!openSet.empty())
    {
        Node current = openSet.top().second;
        openSet.pop();

        if (closedSet[current])
            continue;

        if (current == goal)
            return this->reconstructPath(start, goal);

        closedSet[current] = true;

        auto it = this->graph_.find(current);
        if (it == this->graph_.end())
            continue;

        for (const auto& [neighbor, edgeCost] : it->second)
        {
            Cost tentativeG = this->gScore_[current] + edgeCost;

            auto gs = this->gScore_.find(neighbor);
            if (gs == this->gScore_.end() || tentativeG < gs->second)
            {
                this->cameFrom_[neighbor] = current;
                this->gScore_[neighbor] = tentativeG;

                Cost fScore = tentativeG + heuristic_(neighbor, goal);
                openSet.emplace(fScore, neighbor);
            }
        }
    }

    throw std::runtime_error("Goal node is unreachable");
}


/* ---------------------------
   Bellman-Ford
--------------------------- */

template <typename Node, typename Cost, typename Hash, typename Equal>
void BellmanFord<Node, Cost, Hash, Equal>::buildEdgeList()
{
    edges_.clear();
    for (const auto& [u, neighbors] : graph_)
    {
        for (const auto& [v, w] : neighbors)
        {
            edges_.emplace_back(u, v, w);
        }
    }
}

template <typename Node, typename Cost, typename Hash, typename Equal>
std::unordered_map<Node, Cost, Hash, Equal>
BellmanFord<Node, Cost, Hash, Equal>::computeDistances(const Node& start)
{
    std::unordered_map<Node, Cost, Hash, Equal> dist;

    for (const auto& [node, _] : graph_)
        dist[node] = std::numeric_limits<Cost>::max();

    dist[start] = Cost{};

    for (size_t i = 0; i < graph_.size() - 1; ++i)
    {
        for (const auto& [u, v, w] : edges_)
        {
            if (dist[u] == std::numeric_limits<Cost>::max())
                continue;

            Cost newDist = dist[u] + w;
            if (newDist < dist[v])
                dist[v] = newDist;
        }
    }

    return dist;
}

template <typename Node, typename Cost, typename Hash, typename Equal>
bool BellmanFord<Node, Cost, Hash, Equal>::hasNegativeCycle(const Node& start)
{
    auto dist = computeDistances(start);

    for (const auto& [u, v, w] : edges_)
    {
        if (dist[u] == std::numeric_limits<Cost>::max())
            continue;

        if (dist[u] + w < dist[v])
            return true;
    }

    return false;
}

} } // namespace iar::utils
