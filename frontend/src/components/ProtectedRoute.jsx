export default function ProtectedRoute({ children }) {
  // Allow direct access without login barrier
  return children;
}
