
#pragma once
#include <string>

namespace iar { namespace app {

    template <class U, class V>
    class object_serializer {
    public:

        virtual bool deserialize(U& u, V& v) = 0;
        virtual bool serialize(V& v, U& u) = 0;

        virtual std::string toString(U& u) { return ""; }
    };
} }
