from sentence_transformers import SentenceTransformer, util
import numpy as np

class SemanticSearch:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        # Load the pre-trained model
        self.model = SentenceTransformer(model_name)

    def encode_documents(self, documents):
        # Encode the list of documents into vectors
        return self.model.encode(documents, convert_to_tensor=True)

    def search(self, query, documents, top_k=5):
        # Encode the query into a vector
        query_embedding = self.model.encode(query, convert_to_tensor=True)

        # Encode the documents
        document_embeddings = self.encode_documents(documents)

        # Compute cosine similarities between the query and documents
        cosine_scores = util.pytorch_cos_sim(query_embedding, document_embeddings)[0]

        # Get the top_k highest scores
        top_results = np.argpartition(-cosine_scores, range(top_k))[:top_k]

        # Return the top_k documents and their scores
        return [(documents[idx], cosine_scores[idx].item()) for idx in top_results]

# Example usage
if __name__ == "__main__":
    documents = [
        "The cat sits on the mat.",
        "Dogs are great pets.",
        "There is a cat on the roof.",
        "Birds can fly.",
        "Fish swim in the sea."
    ]
    query = "Where is the cat?"

    searcher = SemanticSearch()
    results = searcher.search(query, documents, top_k=3)

    print("Top 3 results:")
    for doc, score in results:
        print(f"Document: {doc}, Score: {score:.4f}")
