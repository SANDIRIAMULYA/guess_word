def get_feedback(secret: str, guess: str) -> str:
    """
    Compare secret and guess (both 5-letter uppercase).
    Returns 5-char string with:
      'G' = correct letter & correct position (green)
      'O' = correct letter but wrong position (orange)
      'X' = letter not in secret (grey)
    """
    secret = secret.upper()
    guess = guess.upper()
    if len(secret) != 5 or len(guess) != 5:
        raise ValueError("Secret and guess must be 5 letters")

    feedback = ["X"] * 5
    secret_list = list(secret)

    # First pass: exact matches
    for i in range(5):
        if guess[i] == secret[i]:
            feedback[i] = "G"
            secret_list[i] = None

    # Second pass: letters present elsewhere
    for i in range(5):
        if feedback[i] == "X":
            if guess[i] in secret_list:
                feedback[i] = "O"
                secret_list[secret_list.index(guess[i])] = None

    return "".join(feedback)
