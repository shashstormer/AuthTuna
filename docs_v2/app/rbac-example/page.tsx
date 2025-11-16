"use client";
import React from "react";
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check } from 'lucide-react';

const CodeBlock = ({ code, language }: { code: string; language: string }) => {
  const [copied, setCopied] = React.useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group">
      <button
        onClick={copyToClipboard}
        className="absolute top-2 right-2 p-2 rounded bg-gray-700 hover:bg-gray-600 text-white opacity-0 group-hover:opacity-100 transition-opacity"
        aria-label="Copy code"
      >
        {copied ? <Check size={16} /> : <Copy size={16} />}
      </button>
      <SyntaxHighlighter
        language={language}
        style={oneDark}
        className="text-sm md:text-base"
        customStyle={{
          margin: 0,
          borderRadius: '0.5rem',
        }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  );
};

export default function RBACExamplePage() {
  return (
    <div className="max-w-[90vw] md:max-w-6xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20">
      <h1 className="text-3xl font-bold mb-8">RBAC Example: Building Todo Apps with AuthTuna</h1>
      <p className="text-lg mb-6">
        This tutorial demonstrates how to integrate AuthTuna into your applications for authentication, authorization, and role-based access control (RBAC).
        We&apos;ll build two versions of a Todo app: a simple server-side rendered (SSR) app and an advanced single-page application (SPA) with a decoupled frontend.
      </p>

      <div className="mb-8">
        <h2 className="text-2xl font-semibold mb-4">Prerequisites</h2>
        <ul className="list-disc list-inside space-y-2">
          <li>Basic knowledge of Python and FastAPI</li>
          <li>Familiarity with SQL databases (for the simple app)</li>
          <li>Understanding of React and Next.js (for the advanced app)</li>
          <li>MongoDB setup (for the advanced app)</li>
        </ul>
      </div>

      <div className="mb-8">
        <h2 className="text-2xl font-semibold mb-4">Tutorial 1: Simple SSR Todo Application</h2>
        <p className="mb-4">
          In this tutorial, we&apos;ll create a classic monolithic web application where the FastAPI backend handles authentication, business logic, and HTML rendering using Jinja2 templates.
          The key concept is storing application data in the same SQL database as AuthTuna.
        </p>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 1: Set Up Your Database Model</h3>
          <p className="mb-2">
            Create a Todo model that inherits from AuthTuna&apos;s Base class. This ensures the table is managed by AuthTuna&apos;s database system.
            The ForeignKey links each todo to a user, enabling user-specific data scoping.
          </p>
          <CodeBlock code={`# simple/main.py

# 1. Define our custom Todo model
# We inherit from authtuna's 'Base' so it's managed by the same system
class Todo(Base):
    __tablename__ = "todos"
    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    content: Mapped[str] = Column(String, index=True)

    # This is the crucial link to the User model
    user_id: Mapped[str] = Column(String(64), ForeignKey("users.id"))

    # This relationship lets us access todo.user
    user: Mapped["User"] = relationship("User")`} language="python" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 2: Initialize AuthTuna</h3>
          <p className="mb-2">
            Use the <code>init_app(app)</code> function to automatically add authentication routes and session middleware to your FastAPI app.
          </p>
          <CodeBlock code={`# simple/main.py

# 2. Setup FastAPI and Jinja2
app = FastAPI(title="Simple Todo App")
templates = Jinja2Templates(directory="templates")

# 3. Initialize AuthTuna
# This is the magic. It adds all auth routes (/auth/login, /auth/signup)
# and the session middleware.
init_app(app)`} language="python" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 3: Protect Routes and Scope Data</h3>
          <p className="mb-2">
            Use FastAPI&apos;s dependency injection with AuthTuna&apos;s user dependencies to protect routes and ensure users can only access their own data.
          </p>
          <CodeBlock code={`# simple/main.py

@app.get("/todos")
async def get_todos(request: Request, user: User = Depends(get_current_user_optional)):
    """
    Protected route. Only logged-in users can access this.
    It fetches *only* the todos for the current user.
    """
    if not user:
        return RedirectResponse("/")
    todos = []
    async with db_manager.get_db() as db:
        stmt = select(Todo).where(Todo.user_id == user.id)
        result = await db.execute(stmt)
        todos = result.scalars().all()

    return templates.TemplateResponse("todos.html", {
        "request": request,
        "todos": todos,
        "username": user.username
    })

@app.post("/todos/add")
async def add_todo(content: str = Form(...), user: User = Depends(get_current_user)):
    """
    Protected route to add a new todo.
    """
    async with db_manager.get_db() as db:
        new_todo = Todo(content=content, user_id=user.id)
        db.add(new_todo)
        await db.commit()

    return RedirectResponse(url="/todos", status_code=303)`} language="python" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 4: Create the HTML Template</h3>
          <p className="mb-2">
            Use Jinja2 templates to render the UI. The template receives data from the backend and includes links to AuthTuna&apos;s built-in routes.
          </p>
          <CodeBlock code={`<!-- simple/templates/todos.html -->

<div class="container">
    <div class="header">
        <h1>Welcome, {{ username }}!</h1>
        <a href="/auth/logout">Logout</a>
    </div>

    <h2>Your Todos</h2>
    <ul>
        {% for todo in todos %}
            <li>
                <span>{{ todo.content }}</span>
                <a href="/todos/{{ todo.id }}/delete">Delete</a>
            </li>
        {% else %}
            <li>You have no todos yet!</li>
        {% endfor %}
    </ul>

    <form action="/todos/add" method="POST">
        <input type="text" name="content" placeholder="What needs to be done?" required>
        <button type="submit">Add Todo</button>
    </form>
</div>`} language="html" />
        </div>
      </div>

      <div className="mb-8">
        <h2 className="text-2xl font-semibold mb-4">Tutorial 2: Advanced SPA Todo Application</h2>
        <p className="mb-4">
          This tutorial covers a modern decoupled architecture with a FastAPI backend serving JSON APIs and a Next.js frontend.
          We&apos;ll demonstrate multi-tenancy by using AuthTuna for user management and MongoDB for application data.
        </p>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 1: Set Up MongoDB Connection</h3>
          <p className="mb-2">
            Connect to MongoDB separately from AuthTuna&apos;s SQL database. This shows how AuthTuna can work with any database system.
          </p>
          <CodeBlock code={`# advanced/database.py

import os
import motor.motor_asyncio
import dotenv
dotenv.load_dotenv(os.getenv("ENV_FILE_PATH"))

# Create a client to connect to MongoDB
client = motor.motor_asyncio.AsyncIOMotorClient(os.getenv("MONGO_CONNECTION_STRING", "mongodb://localhost:27017"))
# ...
db = client[os.getenv("MONGO_DATABASE_NAME", "authtuna_todo_app")]

# Get a handle to our 'todos' collection
TodoCollection = db.get_collection("todos")`} language="python" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 2: Configure CORS and Initialize AuthTuna</h3>
          <p className="mb-2">
            Add CORS middleware to allow the frontend to communicate with the backend, and initialize AuthTuna.
          </p>
          <CodeBlock code={`# advanced/main.py

# 1. Add CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://localhost(:[0-9]+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Initialize AuthTuna
init_app(app)`} language="python" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 3: Define Pydantic Models</h3>
          <p className="mb-2">
            Create models for handling MongoDB data with proper serialization.
          </p>
          <CodeBlock code={`# advanced/main.py

class Todo(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    content: str
    user_id: str  # This ID comes from authtuna's User model
    org_id: str  # This ID comes from authtuna's Organization model

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )`} language="python" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 4: Implement Organization-Scoped API</h3>
          <p className="mb-2">
            Create an API endpoint that fetches todos based on the user&apos;s organization memberships, demonstrating multi-tenancy.
          </p>
          <CodeBlock code={`# advanced/main.py

@app.get("/api/todos", response_model=List[Todo])
async def get_all_todos_for_user(user: User = Depends(get_current_user)):
    """
    Get all Todos for the current user.
    This demonstrates the "advanced" logic:
    1. Get the current user from AuthTuna.
    2. Get all organizations this user belongs to from AuthTuna.
    3. Get all Todos from MongoDB that belong to any of those organizations.
    """
    # 1. Get orgs from authtuna's db
    user_orgs = await auth_service.orgs.get_user_orgs(user.id)
    org_ids = [org.id for org in user_orgs]

    if not org_ids:
        return []

    # 2. Query MongoDB for todos in those orgs
    todo_cursor = TodoCollection.find({"org_id": {"$in": org_ids}})
    todos = await todo_cursor.to_list(100)
    return todos`} language="python" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 5: Add RBAC-Protected Admin Route</h3>
          <p className="mb-2">
            Use RoleChecker to restrict access to admin-only operations, such as data cleanup.
          </p>
          <CodeBlock code={`# advanced/main.py

@app.post("/api/admin/run-cleanup-step",
          dependencies=[Depends(RoleChecker("Admin"))])
async def run_cleanup_step():
    """
    This is the advanced user deletion task you requested.
    It finds users in authtuna's 'DeletedUser' table with cleanup_counter=0,
    deletes their data from our MongoDB, and increments the counter.
    """
    users_processed = []
    async with db_manager.get_db() as db:
        # 1. Find users in authtuna's DB marked for deletion
        stmt = select(DeletedUser).where(DeletedUser.cleanup_counter == 0)
        # ... (implementation details)
        for user in users_to_cleanup:
            # 2. Delete their application data from MongoDB
            delete_result = await TodoCollection.delete_many(
                {"user_id": user.user_id}
            )
            # ... (update counter)
    return { ... }`} language="python" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 6: Set Up Frontend API Client</h3>
          <p className="mb-2">
            Create a wrapper for API calls that includes credentials for session management.
          </p>
          <CodeBlock code={`// advanced/todo_frontend/lib/api.ts

const API_BASE_URL = "http://localhost:5080";

async function apiFetch(endpoint: string, options: RequestInit = {}) {
  const url = \`\${API_BASE_URL}\${endpoint}\`;
  // ...
  const config: RequestInit = {
    ...options,
    headers: defaultHeaders,
    credentials: "include", // <-- THIS IS THE KEY!
  };
  // ...
  const response = await fetch(url, config);
  // ...
}

export const api = {
  get: (endpoint: string, options?: RequestInit) =>
    apiFetch(endpoint, { ...options, method: "GET" }),

  post: (endpoint: string, body: object, options?: RequestInit) =>
    apiFetch(endpoint, { ...options, method: "POST", body: JSON.stringify(body) }),
  // ...
};`} language="typescript" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 7: Implement Custom Login Page</h3>
          <p className="mb-2">
            Create a custom login form that calls AuthTuna&apos;s API endpoints.
          </p>
          <CodeBlock code={`// advanced/todo_frontend/app/login/page.tsx
'use client';
// ... imports
import { api } from '@/lib/api';

export default function LoginPage() {
  // ... state variables
  const router = useRouter();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    // ...
    try {
      await api.post('/auth/login', {
        username_or_email: username,
        password: password,
      });

      router.push('/');
    } catch (err: unknown) {
      // ... error handling
    }
  };
  // ... return JSX
}`} language="typescript" />
        </div>

        <div className="mb-6">
          <h3 className="text-xl font-medium mb-2">Step 8: Protect Client-Side Pages</h3>
          <p className="mb-2">
            Use client-side logic to check authentication and redirect if necessary. Include links to AuthTuna&apos;s UI for advanced features.
          </p>
          <CodeBlock code={`// advanced/todo_frontend/app/page.tsx
'use client';
// ... imports

export default function Home() {
  // ... state
  const router = useRouter();

  useEffect(() => {
    const fetchTodos = async () => {
      try {
        const responseData = await api.get('/api/todos');
        setTodos(responseData);
      } catch (err: unknown) {
        const error = err as { status?: number };
        if (error.status === 401) {
          router.push('/login');
        } else {
          setError('Failed to fetch todos. Is your backend running?');
        }
      } finally {
        setLoading(false);
      }
    };
    fetchTodos();
  }, [router]);
  // ... handlers for add/delete
  // ... return JSX with link to http://localhost:5080/ui/organizations
}`} language="typescript" />
        </div>
      </div>

      <div className="mt-8">
        <h2 className="text-2xl font-semibold mb-4">Next Steps</h2>
        <ul className="list-disc list-inside space-y-2">
          <li>Clone the full example repository: <a href="https://github.com/shashstormer/Authtuna-todo" className="text-blue-600 hover:underline">Authtuna-todo</a></li>
          <li>Explore AuthTuna&apos;s documentation for more features</li>
          <li>You can config email settings and just explore.</li>
          <li>Implement additional RBAC roles and permissions.</li>
        </ul>
      </div>
    </div>
  );
}
